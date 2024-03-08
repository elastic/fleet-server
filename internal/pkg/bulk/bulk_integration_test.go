// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package bulk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/google/go-cmp/cmp"
)

func TestBulkCreate(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := SetupIndexWithBulk(ctx, t, testPolicy, WithFlushThresholdCount(1))

	tests := []struct {
		Name  string
		Index string
		ID    string
		Err   error
	}{
		{
			Name:  "Empty Id",
			Index: index,
		},
		{
			Name:  "Simple Id",
			Index: index,
			ID:    "elastic",
		},
		{
			Name:  "Single quoted Id",
			Index: index,
			ID:    `'singlequotes'`,
		},
		{
			Name:  "Double quoted Id",
			Index: index,
			ID:    `"doublequotes"`,
			Err:   ErrNoQuotes,
		},
		{
			Name:  "Empty Index",
			Index: "",
			Err: es.ErrElastic{
				Status: 500,
				Type:   "string_index_out_of_bounds_exception",
			},
		},
		{
			Name:  "Unicode Index 豆腐",
			Index: string([]byte{0xe8, 0xb1, 0x86, 0xe8, 0x85, 0x90}),
		},
		{
			Name:  "Invalid utf-8",
			Index: string([]byte{0xfe, 0xfe, 0xff, 0xff}),
			Err: es.ErrElastic{
				Status: 500,
				Type:   "json_parse_exception",
			},
		},
		{
			Name:  "Malformed Index Uppercase",
			Index: "UPPERCASE",
			Err: es.ErrElastic{
				Status: 400,
				Type:   "invalid_index_name_exception",
			},
		},
		{
			Name:  "Malformed Index underscore",
			Index: "_nope",
			Err: es.ErrElastic{
				Status: 400,
				Type:   "invalid_index_name_exception",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			ctx := testlog.SetLogger(t).WithContext(ctx)
			sample := NewRandomSample()
			sampleData := sample.marshal(t)

			// Create
			id, err := bulker.Create(ctx, test.Index, test.ID, sampleData)
			if !EqualElastic(test.Err, err) {
				t.Fatal(err)
			}
			if err != nil {
				return
			}

			if test.ID != "" && id != test.ID {
				t.Error("Expected specified id")
			} else if id == "" {
				t.Error("Expected non-empty id")
			}

			// Read
			var dst testT
			dst.read(t, bulker, ctx, test.Index, id)
			diff := cmp.Diff(sample, dst)
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestBulkCreateBody(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := SetupIndexWithBulk(ctx, t, testPolicy, WithFlushThresholdCount(1))

	tests := []struct {
		Name string
		Body []byte
		Err  error
	}{
		{
			"Empty Body",
			nil,
			nil,
		},
		{
			"Malformed Body",
			[]byte("{nope}"),
			es.ErrInvalidBody,
		},
		{
			"Overflow",
			[]byte(`{"overflow": 99999999999999999999}`),
			es.ErrElastic{
				Status: 400,
				Type:   "document_parsing_exception",
			},
		},
		{
			"Invalid utf-8",
			[]byte{0x7b, 0x22, 0x6f, 0x6b, 0x22, 0x3a, 0x22, 0xfe, 0xfe, 0xff, 0xff, 0x22, 0x7d}, // {"ok":"${BADUTF8}"}
			es.ErrElastic{
				Status: 400,
				Type:   "document_parsing_exception",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			ctx := testlog.SetLogger(t).WithContext(ctx)
			_, err := bulker.Create(ctx, index, "", test.Body)
			if !EqualElastic(test.Err, err) {
				t.Fatalf("expected: %v, got: %v", test.Err, err)
			}
			if err != nil {
				return
			}
		})
	}
}

func TestBulkIndex(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := SetupIndexWithBulk(ctx, t, testPolicy, WithFlushThresholdCount(1))

	sample := NewRandomSample()

	// Index
	id, err := bulker.Index(ctx, index, "", sample.marshal(t))
	if err != nil {
		t.Fatal(err)
	}

	// Read
	var dst testT
	dst.read(t, bulker, ctx, index, id)
	diff := cmp.Diff(sample, dst)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestBulkUpdate(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := SetupIndexWithBulk(ctx, t, testPolicy)

	sample := NewRandomSample()

	// Create
	id, err := bulker.Create(ctx, index, "", sample.marshal(t))
	if err != nil {
		t.Fatal(err)
	}

	// Update
	nVal := "funkycoldmedina"
	fields := UpdateFields{"kwval": nVal}
	data, err := fields.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	err = bulker.Update(ctx, index, id, data, WithRefresh())
	if err != nil {
		t.Fatal(err)
	}

	// Read again, validate update
	var dst2 testT
	dst2.read(t, bulker, ctx, index, id)

	sample.KWVal = nVal
	diff := cmp.Diff(sample, dst2)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestBulkSearch(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := SetupIndexWithBulk(ctx, t, testPolicy)

	sample := NewRandomSample()

	// Create
	_, err := bulker.Create(ctx, index, "", sample.marshal(t), WithRefresh())
	if err != nil {
		t.Fatal(err)
	}

	// Search
	dsl := fmt.Sprintf(`{"query": { "term": {"kwval": "%s"}}}`, sample.KWVal)

	res, err := bulker.Search(ctx, index, []byte(dsl))

	if err != nil {
		t.Fatal(err)
	}

	if res == nil {
		t.Fatal(nil)
	}

	if len(res.Hits) != 1 {
		t.Fatalf("hit mismatch: %d", len(res.Hits))
	}

	var dst3 testT
	if err = json.Unmarshal(res.Hits[0].Source, &dst3); err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(sample, dst3)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestBulkSearchWithIgnoreUnavailable(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	_, bulker := SetupIndexWithBulk(ctx, t, testPolicy)

	// Search
	dsl := fmt.Sprintf(`{"query": { "term": {"kwval": "%s"}}}`, "random")

	res, err := bulker.Search(ctx, ".fleet-policies-do-not-exists-yet", []byte(dsl), WithIgnoreUnavailble())

	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("hit mismatch: %d", len(res.Hits))
	}
	if res == nil {
		t.Fatal(nil)
	}
}

func TestBulkDelete(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := SetupIndexWithBulk(ctx, t, testPolicy)

	sample := NewRandomSample()

	// Create
	id, err := bulker.Create(ctx, index, "", sample.marshal(t))
	if err != nil {
		t.Fatal(err)
	}

	// Delete
	err = bulker.Delete(ctx, index, id)
	if err != nil {
		t.Fatal(err)
	}

	data, err := bulker.Read(ctx, index, id)
	if !errors.Is(err, es.ErrElasticNotFound) || data != nil {
		t.Fatal(err)
	}

	// Attempt to delete again, should not be found
	err = bulker.Delete(ctx, index, id)
	var esErr *es.ErrElastic
	if !errors.As(err, &esErr) || esErr.Status != 404 {
		t.Fatal(err)
	}
}

// This runs a series of CRUD operations through elastic.
// Not a particularly useful benchmark, but gives some idea of memory overhead.
func benchmarkCreate(n int, b *testing.B) {
	b.ReportAllocs()

	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(b).WithContext(ctx)

	index, bulker := SetupIndexWithBulk(ctx, b, testPolicy, WithFlushThresholdCount(n))

	ch := make(chan error, n)
	var wait sync.WaitGroup
	wait.Add(n)
	for i := 0; i < n; i++ {

		go func() {
			defer wait.Done()

			sample := NewRandomSample()
			sampleData := sample.marshal(b)

			for j := 0; j < b.N; j++ {

				// Create
				_, err := bulker.Create(ctx, index, "", sampleData)
				if err != nil {
					ch <- err
				}
			}
		}()
	}
	wait.Wait()
	select {
	case err := <-ch:
		b.Fatal(err)
	default:
	}
}

func BenchmarkCreate(b *testing.B) {
	benchmarks := []int{1, 64, 8192, 16384, 32768, 65536}

	for _, n := range benchmarks {
		bindFunc := func(n int) func(b *testing.B) {
			return func(b *testing.B) {
				benchmarkCreate(n, b)
			}
		}
		b.Run(strconv.Itoa(n), bindFunc(n))
	}
}

// This runs a series of CRUD operations through elastic.
// Not a particularly useful benchmark, but gives some idea of memory overhead.

func benchmarkCRUD(n int, b *testing.B) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(b).WithContext(ctx)

	index, bulker := SetupIndexWithBulk(ctx, b, testPolicy, WithFlushThresholdCount(n))

	fieldUpdate := UpdateFields{"kwval": "funkycoldmedina"}
	fieldData, err := fieldUpdate.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	ch := make(chan error, n)
	var wait sync.WaitGroup
	wait.Add(n)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < n; i++ {
		go func() {
			defer wait.Done()

			sample := NewRandomSample()
			sampleData := sample.marshal(b)

			for j := 0; j < b.N; j++ {

				// Create
				id, err := bulker.Create(ctx, index, "", sampleData)
				if err != nil {
					ch <- err
					return
				}

				// Read
				_, err = bulker.Read(ctx, index, id)
				if err != nil {
					ch <- err
					return
				}

				// Update
				err = bulker.Update(ctx, index, id, fieldData)
				if err != nil {
					ch <- err
					return
				}

				// Delete
				err = bulker.Delete(ctx, index, id)
				if err != nil {
					b.Logf("Delete faile index: %s id: %s err: %v", index, id, err)
					ch <- err
					return
				}
			}
		}()
	}

	wait.Wait()
	select {
	case err := <-ch:
		b.Fatal(err)
	default:
	}
}

func BenchmarkCRUD(b *testing.B) {
	benchmarks := []int{1, 64, 8192, 16384, 32768, 65536}

	for _, n := range benchmarks {
		bindFunc := func(n int) func(b *testing.B) {
			return func(b *testing.B) {
				benchmarkCRUD(n, b)
			}
		}
		b.Run(strconv.Itoa(n), bindFunc(n))
	}
}
