// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

const payload = `{"_id" : "1", "_index" : "test"}`

func TestMultiWriteOptionsReachElasticsearch(t *testing.T) {
	tests := []struct {
		name string
		give func(*Bulker, context.Context, []MultiOp, ...Opt) ([]BulkIndexerResponseItem, error)
		body string
		opts []Opt
		want string
	}{
		{
			name: "a multi-create forwards refresh",
			give: (*Bulker).MCreate,
			body: `{}`,
			want: `{"create":{"_id":"1","_index":"testidx"}}`,
		},
		{
			name: "a multi-index forwards refresh",
			give: (*Bulker).MIndex,
			body: `{}`,
			want: `{"index":{"_id":"1","_index":"testidx"}}`,
		},
		{
			name: "a multi-update forwards refresh and conflict retries",
			give: (*Bulker).MUpdate,
			body: `{"doc":{}}`,
			opts: []Opt{WithRetryOnConflict(3)},
			want: `{"update":{"_id":"1","retry_on_conflict":3,"_index":"testidx"}}`,
		},
		{
			name: "a multi-delete forwards refresh",
			give: (*Bulker).MDelete,
			want: `{"delete":{"_id":"1","_index":"testidx"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var refresh string
				var requestBody []byte
				transport := performFunc(func(req *http.Request) (*http.Response, error) {
					refresh = req.URL.Query().Get("refresh")
					body, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					requestBody = body
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"items":[{"index":{"status":200}}]}`)),
					}, nil
				})
				bulker := NewBulker(transport, nil, WithFlushInterval(time.Hour))
				ctx := runBulker(t, bulker)
				writeCtx, cancel := context.WithTimeout(ctx, time.Minute)
				defer cancel()

				ops := []MultiOp{{Index: testIndex, ID: "1", Body: []byte(tt.body)}}
				opts := append([]Opt{WithRefresh(), WithFlushAfter(1)}, tt.opts...)
				items, err := tt.give(bulker, writeCtx, ops, opts...)
				require.NoError(t, err)
				require.Len(t, items, len(ops))

				assert.Equal(t, "true", refresh)

				metadata, _, _ := strings.Cut(string(requestBody), "\n")
				assert.JSONEq(t, tt.want, metadata)
			})
		})
	}
}

// Test throughput of creating multiOps
func BenchmarkMultiUpdateMock(b *testing.B) {
	// Allocate, but don't run.  Stub the client.
	bulker := NewBulker(nil, nil)
	defer close(bulker.ch)

	go func() {
		for v := range bulker.ch {
			v.ch <- respT{nil, v.idx, nil}
		}
	}()

	body := []byte(payload)

	benchmarks := []int{1, 8, 64, 4096, 32768, 131072}

	// Create the samples outside the loop to avoid accounting
	max := 0
	for _, v := range benchmarks {
		if max < v {
			max = v
		}
	}

	// Create the ops
	ops := make([]MultiOp, 0, max)
	for i := 0; i < max; i++ {
		ops = append(ops, MultiOp{
			ID:    "abba",
			Index: "bogus",
			Body:  body,
		})
	}

	for _, n := range benchmarks {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			ctx := testlog.SetLogger(b).WithContext(context.Background())
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := bulker.MUpdate(ctx, ops[:n]); err != nil {
					b.Fatal(err)
				}

			}
		})
	}

}
