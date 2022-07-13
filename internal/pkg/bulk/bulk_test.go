// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
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
		Body:       ioutil.NopCloser(&body),
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
			_ = testlog.SetLogger(t)
			ctx, cancelF := context.WithCancel(context.Background())

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()

				test.test(t, ctx)
			}()

			time.Sleep(time.Millisecond)
			cancelF()

			wg.Wait()
		})
	}
}

func benchmarkMockBulk(b *testing.B, samples [][]byte) {
	b.ReportAllocs()
	_ = testlog.SetLogger(b)

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
					b.Logf("Delete failed index: %s id: %s", index, id)
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
