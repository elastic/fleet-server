// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO:
// WithREfresh() options
// Delete not found?

type mockBulkTransport struct {
}

func (m *mockBulkTransport) Perform(req *http.Request) (*http.Response, error) {

	type mockFrameT struct {
		Index  json.RawMessage `json:"index,omitempty"`
		Delete json.RawMessage `json:"delete,omitempty"`
		Create json.RawMessage `json:"create,omitempty"`
		Update json.RawMessage `json:"update,omitempty"`
	}

	type mockEmptyT struct {
	}

	mockResponse := []byte(`{"index":{"_index":"test","_type":"_doc","_id":"1","_version":1,"result":"created","_shards":{"total":2,"successful":1,"failed":0},"status":201,"_seq_no":0,"_primary_term":1}},`)

	var body bytes.Buffer

	// Write framing
	body.WriteString(`{"items": [`)

	cnt := 0

	skip := false
	decoder := json.NewDecoder(req.Body)
	for decoder.More() {
		if skip {
			skip = false
			var e mockEmptyT
			if err := decoder.Decode(&e); err != nil {
				return nil, err
			}
		} else {
			var frame mockFrameT
			if err := decoder.Decode(&frame); err != nil {
				return nil, err
			}

			// Which op
			switch {
			case frame.Index != nil:
				skip = true
			case frame.Delete != nil:
			case frame.Create != nil:
				skip = true
			case frame.Update != nil:
				skip = true
			default:
				return nil, errors.New("Unknown op")
			}

			// write mocked response
			_, err := body.Write(mockResponse)

			if err != nil {
				return nil, err
			}

			cnt += 1
		}
	}

	if cnt > 0 {
		body.Truncate(body.Len() - 1)
	}

	// Write trailer
	body.WriteString(`], "took": 1, "errors": false}`)

	resp := &http.Response{
		Request:    req,
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(&body),
	}

	return resp, nil
}

// API should exit quickly if cancelled.
// Note: In the real world, the transaction may already be in flight,
// cancelling a call does not mean the transaction did not occur.
func TestCancelCtx(t *testing.T) {
	// create a bulker, but don't bother running it
	bulker := NewBulker(nil, nil)

	tests := []struct {
		name string
		test func(t *testing.T, ctx context.Context)
	}{
		{
			"create",
			func(t *testing.T, ctx context.Context) {
				id, err := bulker.Create(ctx, "testidx", "", []byte(`{"hey":"now"}`))

				if id != "" {
					t.Error("Expected empty id on context cancel:", id)
				}

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"read",
			func(t *testing.T, ctx context.Context) {
				data, err := bulker.Read(ctx, "testidx", "11")

				if data != nil {
					t.Error("Expected empty data on context cancel:", data)
				}

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"update",
			func(t *testing.T, ctx context.Context) {
				err := bulker.Update(ctx, "testidx", "11", []byte(`{"now":"hey"}`))

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"delete",
			func(t *testing.T, ctx context.Context) {
				err := bulker.Delete(ctx, "testidx", "11")

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"index",
			func(t *testing.T, ctx context.Context) {
				id, err := bulker.Index(ctx, "testidx", "", []byte(`{"hey":"now"}`))

				if id != "" {
					t.Error("Expected empty id on context cancel:", id)
				}

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"search",
			func(t *testing.T, ctx context.Context) {
				res, err := bulker.Search(ctx, "testidx", []byte(`{"hey":"now"}`))

				if res != nil {
					t.Error("Expected empty result on context cancel:", res)
				}

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"mcreate",
			func(t *testing.T, ctx context.Context) {
				res, err := bulker.MCreate(ctx, []MultiOp{{Index: "testidx", Body: []byte(`{"hey":"now"}`)}})

				if res != nil {
					t.Error("Expected empty result on context cancel:", res)
				}

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"mindex",
			func(t *testing.T, ctx context.Context) {
				res, err := bulker.MIndex(ctx, []MultiOp{{Index: "testidx", Body: []byte(`{"hey":"now"}`)}})

				if res != nil {
					t.Error("Expected empty result on context cancel:", res)
				}

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"mupdate",
			func(t *testing.T, ctx context.Context) {
				res, err := bulker.MUpdate(ctx, []MultiOp{{Index: "testidx", ID: "umm", Body: []byte(`{"hey":"now"}`)}})

				if res != nil {
					t.Error("Expected empty result on context cancel:", res)
				}

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
		{
			"mdelete",
			func(t *testing.T, ctx context.Context) {
				res, err := bulker.MDelete(ctx, []MultiOp{{Index: "testidx", ID: "myid"}})

				if res != nil {
					t.Error("Expected empty result on context cancel:", res)
				}

				if !errors.Is(err, context.Canceled) {
					t.Error("Expected context cancel err: ", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancelF := context.WithCancel(context.Background())

			cancelF()
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()

				test.test(t, ctx)
			}()

			wg.Wait()
		})
	}
}

// verify that child bulker stops when bulker ctx cancelled
func TestCancelCtxChildBulker(t *testing.T) {
	bulker := NewBulker(nil, nil)

	ctx, cancelF := context.WithCancel(context.Background())

	outputMap := make(map[string]map[string]interface{})
	outputMap["remote"] = map[string]interface{}{
		"type":          "remote_elasticsearch",
		"hosts":         []interface{}{"https://remote-es:443"},
		"service_token": "token1",
	}

	cancelF()
	childBulker, _, err := bulker.CreateAndGetBulker(ctx, zerolog.Nop(), "remote", outputMap)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		_, err := childBulker.APIKeyAuth(ctx, apikey.APIKey{})

		if !errors.Is(err, context.Canceled) {
			t.Error("Expected context cancel err: ", err)
		}
	}()

	wg.Wait()
}

func benchmarkMockBulk(b *testing.B, samples [][]byte) {
	mock := &mockBulkTransport{}

	ctx, cancelF := context.WithCancel(context.Background())
	defer cancelF()

	n := len(samples)
	bulker := NewBulker(mock, nil, WithFlushThresholdCount(n))

	var waitBulker sync.WaitGroup
	waitBulker.Add(1)
	go func() {
		defer waitBulker.Done()
		if err := bulker.Run(ctx); !errors.Is(err, context.Canceled) {
			b.Error(err)
		}
	}()

	fieldUpdate := UpdateFields{"kwval": "funkycoldmedina"}
	fieldData, err := fieldUpdate.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	index := "fakeIndex"

	var wait sync.WaitGroup
	wait.Add(n)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < n; i++ {
		go func(sampleData []byte) {
			defer wait.Done()

			for j := 0; j < b.N; j++ {
				// Create
				id, err := bulker.Create(ctx, index, "", sampleData)
				if err != nil {
					b.Error(err)
				}
				// Index
				_, err = bulker.Index(ctx, index, id, sampleData)
				if err != nil {
					b.Error(err)
				}

				// Update
				err = bulker.Update(ctx, index, id, fieldData)
				if err != nil {
					b.Error(err)
				}

				// Delete
				err = bulker.Delete(ctx, index, id)
				if err != nil {
					b.Error(err)
				}
			}
		}(samples[i])
	}

	wait.Wait()
	cancelF()
	waitBulker.Wait()
}

func BenchmarkMockBulk(b *testing.B) {
	benchmarks := []int{1, 8, 64, 4096, 32768}

	// Create the samples outside the loop to avoid accounting
	max := 0
	for _, v := range benchmarks {
		if max < v {
			max = v
		}
	}

	samples := make([][]byte, 0, max)
	for i := 0; i < max; i++ {
		s := NewRandomSample()
		samples = append(samples, s.marshal(b))
	}

	for _, n := range benchmarks {
		bindFunc := func(n int) func(b *testing.B) {
			return func(b *testing.B) {
				benchmarkMockBulk(b, samples[:n])
			}
		}
		b.Run(strconv.Itoa(n), bindFunc(n))
	}
}
<<<<<<< HEAD
=======

type performFunc func(*http.Request) (*http.Response, error)

func (f performFunc) Perform(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestMSearch(t *testing.T) {
	var (
		errFirstFlushFailed  = errors.New("first flush failed")
		errSecondFlushFailed = errors.New("second flush failed")
	)

	indices := map[string]struct {
		body string
		err  error
	}{
		"ok": {
			body: `{"responses":[{"status":200,"hits":{"hits":[]}}],"took":1}`,
		},
		"rejected": {
			body: `{"responses":[{"status":429,"error":{"type":"es_rejected_execution_exception","reason":"rejected"}}],"took":1}`,
		},
		"first-failed": {
			err: errFirstFlushFailed,
		},
		"second-failed": {
			err: errSecondFlushFailed,
		},
	}

	tests := []struct {
		name         string
		indices      []string
		wantStatuses []int
		wantErrs     []error
	}{
		{
			name:         "successful and rejected searches return no request error",
			indices:      []string{"ok", "rejected"},
			wantStatuses: []int{http.StatusOK, http.StatusTooManyRequests},
		},
		{
			name:         "a failed request error is returned alongside per-search responses",
			indices:      []string{"first-failed", "rejected"},
			wantStatuses: []int{0, http.StatusTooManyRequests},
			wantErrs:     []error{errFirstFlushFailed},
		},
		{
			name:         "distinct errors from multiple failed requests are returned once each",
			indices:      []string{"first-failed", "second-failed", "first-failed", "rejected"},
			wantStatuses: []int{0, 0, 0, http.StatusTooManyRequests},
			wantErrs:     []error{errFirstFlushFailed, errSecondFlushFailed},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				transport := performFunc(func(req *http.Request) (*http.Response, error) {
					var meta struct {
						Index string `json:"index"`
					}
					if err := json.NewDecoder(req.Body).Decode(&meta); err != nil {
						return nil, err
					}
					if call := calls.Add(1); call > 1 {
						// Stagger later flushes so earlier errors reach MSearch first.
						time.Sleep(time.Duration(call-1) * time.Second)
					}
					res := indices[meta.Index]
					if res.err != nil {
						return nil, res.err
					}
					resp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(res.body))}
					return resp, nil
				})
				bulker := NewBulker(transport, nil, WithFlushInterval(time.Hour))
				ctx := runBulker(t, bulker)

				ops := make([]MultiOp, len(tt.indices))
				for i, index := range tt.indices {
					ops[i] = MultiOp{Index: index, Body: []byte(`{}`)}
				}
				// WithFlushAfter(1) sends each search in its own request.
				items, err := bulker.MSearch(ctx, ops, WithFlushAfter(1))
				if len(tt.wantErrs) == 0 {
					require.NoError(t, err, "MSearch returned unexpected error")
				}
				for _, wantErr := range tt.wantErrs {
					require.ErrorIs(t, err, wantErr, "MSearch must return error %v", wantErr)
					errCount := strings.Count(err.Error(), wantErr.Error())
					assert.Equal(t, 1, errCount, "error %q must not be repeated in %q", wantErr, err)
				}
				require.Len(t, items, len(ops), "MSearch must return one item per search")
				statuses := make([]int, len(items))
				for i, item := range items {
					statuses[i] = item.Status
					wantReqErr := indices[tt.indices[i]].err
					if wantReqErr == nil {
						assert.NoError(t, item.RequestError, "items[%d] must not have a request error", i)
					} else {
						assert.ErrorIs(t, item.RequestError, wantReqErr, "items[%d] request error", i)
					}
				}
				assert.ElementsMatch(t, tt.wantStatuses, statuses, "unexpected search response statuses")
			})
		})
	}
}

// TestMSearchFlushAfter verifies that the searches are sent as soon as the number of searches
// given to WithFlushAfter are queued, without waiting for the flush interval.
func TestMSearchFlushAfter(t *testing.T) {
	ops := []MultiOp{
		{Index: testIndex, Body: []byte(`{}`)},
		{Index: testIndex, Body: []byte(`{}`)},
	}
	bulker := NewBulker(&fixedTransport{body: msearchResponse(len(ops))}, nil, WithFlushInterval(time.Hour))
	ctx := runBulker(t, bulker)

	searchCtx, cancelSearch := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSearch()
	items, err := bulker.MSearch(searchCtx, ops, WithFlushAfter(len(ops)))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != len(ops) {
		t.Fatalf("got %d items, want %d", len(items), len(ops))
	}
}

// runBulker runs the bulker until the end of the test and returns its context.
func runBulker(t *testing.T, bulker *Bulker) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := bulker.Run(ctx); !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return ctx
}
>>>>>>> 02598fa (Fix error handling in batched policy searches (#8362))
