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
	"sync/atomic"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/rs/zerolog"
)

const (
	testDocID      = "test-id"
	testHTTPStatus = "200 OK"
	testHTTPProto  = "HTTP/1.1"

	testESConflictBody = `{"took":1,"errors":true,"items":[{"create":{"_id":"test-id","status":409,"error":{"type":"version_conflict_engine_exception","reason":"version conflict"}}}]}`
	testESSuccessBody  = `{"took":1,"errors":false,"items":[{"create":{"_id":"test-id","status":201}}]}`
)

// TODO:
// WithREfresh() options
// Delete not found?

// conflictThenSuccessTransport returns a 409 version conflict for the first
// Create request and a 201 success for all subsequent requests.
type conflictThenSuccessTransport struct {
	calls atomic.Int32
}

func (m *conflictThenSuccessTransport) Perform(req *http.Request) (*http.Response, error) {
	var body string
	if m.calls.Add(1) == 1 {
		body = testESConflictBody
	} else {
		body = testESSuccessBody
	}
	return &http.Response{
		Request:    req,
		StatusCode: 200,
		Status:     testHTTPStatus,
		Proto:      testHTTPProto,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}, nil
}

func TestCreateRetriesOnVersionConflict(t *testing.T) {
	mock := &conflictThenSuccessTransport{}

	bulker := NewBulker(mock, nil, WithFlushThresholdCount(1))
	go func() { _ = bulker.Run(t.Context()) }()

	id, err := bulker.Create(t.Context(), "test-index", testDocID, []byte(`{"field":"value"}`))
	if err != nil {
		t.Fatalf("expected Create to succeed after retry, got: %v", err)
	}
	if id != testDocID {
		t.Errorf("expected document ID %q, got %q", testDocID, id)
	}
	if calls := mock.calls.Load(); calls != 2 {
		t.Errorf("expected 2 transport calls (1 conflict + 1 retry), got %d", calls)
	}
}

func TestCreateReturnsConflictAfterMaxRetries(t *testing.T) {
	// Transport that always returns 409.
	always409 := func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			Request:    req,
			StatusCode: 200,
			Status:     testHTTPStatus,
			Proto:      testHTTPProto,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(bytes.NewBufferString(testESConflictBody)),
		}, nil
	}

	bulker := NewBulker(transportFunc(always409), nil, WithFlushThresholdCount(1))
	go func() { _ = bulker.Run(t.Context()) }()

	_, err := bulker.Create(t.Context(), "test-index", testDocID, []byte(`{"field":"value"}`))
	if !errors.Is(err, es.ErrElasticVersionConflict) {
		t.Fatalf("expected ErrElasticVersionConflict after exhausting retries, got: %v", err)
	}
}

func TestCreateRetriesOnDeadlineExceeded(t *testing.T) {
	var calls atomic.Int32
	transport := transportFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, context.DeadlineExceeded
		}
		return &http.Response{
			Request:    req,
			StatusCode: 200,
			Status:     testHTTPStatus,
			Proto:      testHTTPProto,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(bytes.NewBufferString(testESSuccessBody)),
		}, nil
	})

	bulker := NewBulker(transport, nil, WithFlushThresholdCount(1))
	go func() { _ = bulker.Run(t.Context()) }()

	id, err := bulker.Create(t.Context(), "test-index", testDocID, []byte(`{"field":"value"}`))
	if err != nil {
		t.Fatalf("expected Create to succeed after retry, got: %v", err)
	}
	if id != testDocID {
		t.Errorf("expected document ID %q, got %q", testDocID, id)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("expected 2 transport calls (1 timeout + 1 retry), got %d", n)
	}
}

func TestCreateReturnsDeadlineExceededAfterMaxRetries(t *testing.T) {
	var calls atomic.Int32
	transport := transportFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, context.DeadlineExceeded
	})

	bulker := NewBulker(transport, nil, WithFlushThresholdCount(1))
	go func() { _ = bulker.Run(t.Context()) }()

	_, err := bulker.Create(t.Context(), "test-index", testDocID, []byte(`{"field":"value"}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded after exhausting retries, got: %v", err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("expected 3 transport calls (max retries), got %d", n)
	}
}

func TestCreateDoesNotRetryWhenCallerContextCanceled(t *testing.T) {
	var calls atomic.Int32
	ready := make(chan struct{})
	transport := transportFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(ready) // signal that the transport was entered
		<-req.Context().Done()
		return nil, req.Context().Err()
	})

	callerCtx, cancel := context.WithCancel(t.Context())
	bulker := NewBulker(transport, nil, WithFlushThresholdCount(1))
	go func() { _ = bulker.Run(t.Context()) }()

	done := make(chan error, 1)
	go func() {
		_, err := bulker.Create(callerCtx, "test-index", testDocID, []byte(`{"field":"value"}`))
		done <- err
	}()

	<-ready // wait until the transport is blocked, then cancel the caller
	cancel()

	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("expected exactly 1 transport call (no retry after caller cancel), got %d", n)
	}
}

// transportFunc adapts a function to the esapi.Transport interface.
type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) Perform(req *http.Request) (*http.Response, error) { return f(req) }

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
			wg.Go(func() {

				test.test(t, ctx)
			})

			wg.Wait()
		})
	}
}

// verify that child bulker stops when bulker ctx cancelled
func TestCancelCtxChildBulker(t *testing.T) {
	bulker := NewBulker(nil, nil)

	ctx, cancelF := context.WithCancel(context.Background())

	outputMap := make(map[string]map[string]any)
	outputMap["remote"] = map[string]any{
		"type":          "remote_elasticsearch",
		"hosts":         []any{"https://remote-es:443"},
		"service_token": "token1",
	}

	cancelF()
	childBulker, _, err := bulker.CreateAndGetBulker(ctx, zerolog.Nop(), "remote", outputMap)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {

		_, err := childBulker.APIKeyAuth(ctx, apikey.APIKey{})

		if !errors.Is(err, context.Canceled) {
			t.Error("Expected context cancel err: ", err)
		}
	})

	wg.Wait()
}

func benchmarkMockBulk(b *testing.B, samples [][]byte) {
	mock := &mockBulkTransport{}

	ctx, cancelF := context.WithCancel(context.Background())
	defer cancelF()

	n := len(samples)
	bulker := NewBulker(mock, nil, WithFlushThresholdCount(n))

	var waitBulker sync.WaitGroup
	waitBulker.Go(func() {
		if err := bulker.Run(ctx); !errors.Is(err, context.Canceled) {
			b.Error(err)
		}
	})

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
	for i := range n {
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
