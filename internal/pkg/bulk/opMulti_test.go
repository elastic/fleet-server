// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"context"
	"io"
	"net/http"
	"net/url"
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
		name        string
		method      func(*Bulker, context.Context, []MultiOp, ...Opt) ([]BulkIndexerResponseItem, error)
		body        []byte
		opts        []Opt
		want        string
		wantRefresh bool
	}{
		{
			name:   "a multi-create uses defaults",
			method: (*Bulker).MCreate,
			want:   `{"create":{"_id":"1","_index":"testidx"}}`,
		},
		{
			name:        "a multi-create forwards refresh",
			method:      (*Bulker).MCreate,
			body:        []byte(`{}`),
			opts:        []Opt{WithRefresh(), WithFlushAfter(1)},
			want:        `{"create":{"_id":"1","_index":"testidx"}}`,
			wantRefresh: true,
		},
		{
			name:        "a multi-index forwards refresh",
			method:      (*Bulker).MIndex,
			body:        []byte(`{}`),
			opts:        []Opt{WithRefresh(), WithFlushAfter(1)},
			want:        `{"index":{"_id":"1","_index":"testidx"}}`,
			wantRefresh: true,
		},
		{
			name:        "a multi-update forwards refresh and conflict retries",
			method:      (*Bulker).MUpdate,
			body:        []byte(`{"doc":{}}`),
			opts:        []Opt{WithRefresh(), WithFlushAfter(1), WithRetryOnConflict(3)},
			want:        `{"update":{"_id":"1","retry_on_conflict":3,"_index":"testidx"}}`,
			wantRefresh: true,
		},
		{
			name:        "a multi-delete forwards refresh",
			method:      (*Bulker).MDelete,
			opts:        []Opt{WithRefresh(), WithFlushAfter(1)},
			want:        `{"delete":{"_id":"1","_index":"testidx"}}`,
			wantRefresh: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := []MultiOp{{Index: testIndex, ID: "1", Body: tt.body}}
			var bulkerOpts []BulkOpt
			if len(tt.opts) > 0 {
				bulkerOpts = []BulkOpt{WithFlushInterval(time.Hour)}
			}
			wantQuery := url.Values{}
			if tt.wantRefresh {
				wantQuery.Set("refresh", "true")
			}

			var query url.Values
			var requestBody []byte
			recordBulkRequest := performFunc(func(req *http.Request) (*http.Response, error) {
				query = req.URL.Query()
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				requestBody = body
				response := &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"items":[{"index":{"status":200}}]}`)),
				}
				return response, nil
			})

			synctest.Test(t, func(t *testing.T) {
				bulker := NewBulker(recordBulkRequest, nil, bulkerOpts...)
				ctx, cancel := context.WithTimeout(runBulker(t, bulker), time.Minute)
				defer cancel()

				items, err := tt.method(bulker, ctx, ops, tt.opts...)
				require.NoError(t, err)

				require.Len(t, items, len(ops))

				assert.Equal(t, wantQuery, query)

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
