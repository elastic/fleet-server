// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package checkin

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"github.com/google/go-cmp/cmp"

	tst "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
)

type CustomBulk struct {
	tst.MockBulk

	ops []bulk.MultiOp
}

func (m *CustomBulk) MUpdate(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	m.ops = append(m.ops, ops...)
	return nil, nil
}

// Test simple,
// Test with fields
// Test with seq no

func TestBulkSimple(t *testing.T) {
	start := time.Now()

	var mockBulk CustomBulk

	bc := NewBulkCheckin(&mockBulk)

	cases := []struct {
		desc  string
		id    string
		meta  []byte
		seqno sqn.SeqNo
	}{
		{
			"Simple case",
			"simpleId",
			nil,
			nil,
		},
		{
			"Singled field case",
			"singleFieldId",
			[]byte(`{"hey":"now"}`),
			nil,
		},
		{
			"Multi field case",
			"multiFieldId",
			[]byte(`{"hey":"now","brown":"cow"}`),
			nil,
		},
		{
			"Multi field nested case",
			"multiFieldNestedId",
			[]byte(`{"hey":"now","wee":{"little":"doggie"}}`),
			nil,
		},
		{
			"Simple case with seqNo",
			"simpleseqno",
			nil,
			sqn.SeqNo{1, 2, 3, 4},
		},
		{
			"Field case with seqNo",
			"simpleseqno",
			[]byte(`{"uncle":"fester"}`),
			sqn.SeqNo{5, 6, 7, 8},
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {

			if err := bc.CheckIn(c.id, c.meta, c.seqno); err != nil {
				t.Fatal(err)
			}

			if err := bc.flush(context.Background()); err != nil {
				t.Fatal(err)
			}

			if len(mockBulk.ops) != 1 {
				t.Fatal("Expected one op")
			}

			op := mockBulk.ops[0]

			mockBulk.ops = nil

			// deserialize the response
			if op.Id != c.id {
				t.Error("Wrong id")
			}

			if op.Index != dl.FleetAgents {
				t.Error("Wrong index")
			}

			type updateT struct {
				LastCheckin string          `json:"last_checkin"`
				UpdatedAt   string          `json:"updated_at"`
				Meta        json.RawMessage `json:"local_metadata"`
				SeqNo       sqn.SeqNo       `json:"action_seq_no"`
			}

			m := make(map[string]updateT)
			if err := json.Unmarshal(op.Body, &m); err != nil {
				t.Error(err)
			}

			sub, ok := m["doc"]
			if !ok {
				t.Fatal("expected doc")
			}

			validateTimestamp(t, start.Truncate(time.Second), sub.LastCheckin)
			validateTimestamp(t, start.Truncate(time.Second), sub.UpdatedAt)

			if c.seqno != nil {
				if cdiff := cmp.Diff(c.seqno, sub.SeqNo); cdiff != "" {
					t.Error(cdiff)
				}
			}

			if c.meta != nil && bytes.Compare(c.meta, sub.Meta) != 0 {
				t.Error("meta doesn't match up")
			}

		})
	}
}

func validateTimestamp(t *testing.T, start time.Time, ts string) {

	if t1, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Error("expected rfc3999")
	} else if start.After(t1) {
		t.Error("timestamp in the past")
	}
}

func benchmarkBulk(n int, flush bool, b *testing.B) {
	b.ReportAllocs()

	l := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(l)

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	var mockBulk tst.MockBulk

	bc := NewBulkCheckin(mockBulk)

	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := xid.New().String()
		ids = append(ids, id)
	}

	for i := 0; i < b.N; i++ {

		for _, id := range ids {
			err := bc.CheckIn(id, nil, nil)
			if err != nil {
				b.Fatal(err)
			}
		}

		if flush {
			err := bc.flush(context.Background())
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkBulk_1(b *testing.B)      { benchmarkBulk(1, false, b) }
func BenchmarkBulk_64(b *testing.B)     { benchmarkBulk(64, false, b) }
func BenchmarkBulk_8192(b *testing.B)   { benchmarkBulk(8192, false, b) }
func BenchmarkBulk_37268(b *testing.B)  { benchmarkBulk(37268, false, b) }
func BenchmarkBulk_131072(b *testing.B) { benchmarkBulk(131072, false, b) }
func BenchmarkBulk_262144(b *testing.B) { benchmarkBulk(262144, false, b) }

func BenchmarkBulkFlush_1(b *testing.B)      { benchmarkBulk(1, true, b) }
func BenchmarkBulkFlush_64(b *testing.B)     { benchmarkBulk(64, true, b) }
func BenchmarkBulkFlush_8192(b *testing.B)   { benchmarkBulk(8192, true, b) }
func BenchmarkBulkFlush_37268(b *testing.B)  { benchmarkBulk(37268, true, b) }
func BenchmarkBulkFlush_131072(b *testing.B) { benchmarkBulk(131072, true, b) }
func BenchmarkBulkFlush_262144(b *testing.B) { benchmarkBulk(262144, true, b) }
