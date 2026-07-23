// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//nolint:dupl // duplicate lines used in tests
package bulk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
)

// fixedTransport returns a pre-built response body on every Perform call.
// It has no per-request parsing logic, so it doesn't contribute allocations
// or CPU time that would obscure changes to the flush functions under test.
type fixedTransport struct {
	body []byte
}

func (t *fixedTransport) Perform(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(bytes.NewReader(t.body)),
	}, nil
}

// drainQueue empties the response channels written by a flush call so the
// same queue can be reused in the next benchmark iteration.
func drainQueue(queue queueT) {
	for n := queue.head; n != nil; n = n.next {
		<-n.ch
	}
}

// --- BenchmarkFlushSearch ---

func msearchResponse(n int) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"responses":[`)
	for i := range n {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"status":200,"took":1,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`)
	}
	buf.WriteString(`],"took":1}`)
	return buf.Bytes()
}

func makeSearchQueue(b *testing.B, bulker *Bulker, n int) queueT {
	b.Helper()
	body := []byte(`{"query":{"match_all":{}}}`)
	var head, tail *bulkT
	var pending int
	for i := range n {
		blk := &bulkT{ch: make(chan respT, 1), idx: int32(i)}
		if err := bulker.writeMsearchMeta(&blk.buf, "test", nil, nil, false); err != nil {
			b.Fatal(err)
		}
		if err := bulker.writeMsearchBody(&blk.buf, body); err != nil {
			b.Fatal(err)
		}
		pending += blk.buf.Len()
		if tail != nil {
			tail.next = blk
		} else {
			head = blk
		}
		tail = blk
	}
	return queueT{ty: kQueueSearch, cnt: n, head: head, pending: pending}
}

func BenchmarkFlushSearch(b *testing.B) {
	for _, n := range []int{1, 8, 64, 4096, 32768} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			bulker := NewBulker(&fixedTransport{body: msearchResponse(n)}, nil)
			queue := makeSearchQueue(b, bulker, n)
			ctx := context.Background()
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				if err := bulker.flushSearch(ctx, queue); err != nil {
					b.Fatal(err)
				}
				drainQueue(queue)
			}
		})
	}
}

// --- BenchmarkFlushRead ---

func mgetResponse(n int) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"docs":[`)
	for i := range n {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"_id":"`)
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(`","_version":1,"_seq_no":0,"found":true,"_source":{}}`)
	}
	buf.WriteString(`]}`)
	return buf.Bytes()
}

func makeReadQueue(b *testing.B, bulker *Bulker, n int) queueT {
	b.Helper()
	var head, tail *bulkT
	var pending int
	for i := range n {
		blk := &bulkT{ch: make(chan respT, 1), idx: int32(i)}
		if err := bulker.writeMget(&blk.buf, "test", strconv.Itoa(i)); err != nil {
			b.Fatal(err)
		}
		pending += blk.buf.Len()
		if tail != nil {
			tail.next = blk
		} else {
			head = blk
		}
		tail = blk
	}
	return queueT{ty: kQueueRead, cnt: n, head: head, pending: pending}
}

func BenchmarkFlushRead(b *testing.B) {
	for _, n := range []int{1, 8, 64, 4096, 32768} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			bulker := NewBulker(&fixedTransport{body: mgetResponse(n)}, nil)
			queue := makeReadQueue(b, bulker, n)
			ctx := context.Background()
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				if err := bulker.flushRead(ctx, queue); err != nil {
					b.Fatal(err)
				}
				drainQueue(queue)
			}
		})
	}
}

// --- BenchmarkFlushAPIKeyUpdate ---

func makeAPIKeyQueue(b *testing.B, bulker *Bulker, n int) queueT {
	b.Helper()
	roles := json.RawMessage(`{"fleet-server":{"cluster":["monitor"]}}`)
	roleHash := "abc123"
	var head, tail *bulkT
	var pending int
	for i := range n {
		id := strconv.Itoa(i)
		blk := &bulkT{ch: make(chan respT, 1), idx: int32(i)}
		req := apiKeyUpdateRequest{
			ID:        id,
			Roles:     roles,
			RolesHash: roleHash,
		}
		body, err := json.Marshal(req)
		if err != nil {
			b.Fatal(err)
		}
		if err := bulker.writeBulkMeta(&blk.buf, ActionUpdateAPIKey.String(), "", id, ""); err != nil {
			b.Fatal(err)
		}
		if err := bulker.writeBulkBody(&blk.buf, ActionUpdateAPIKey, body); err != nil {
			b.Fatal(err)
		}
		pending += blk.buf.Len()
		if tail != nil {
			tail.next = blk
		} else {
			head = blk
		}
		tail = blk
	}
	return queueT{ty: kQueueAPIKeyUpdate, cnt: n, head: head, pending: pending}
}

func BenchmarkFlushAPIKeyUpdate(b *testing.B) {
	for _, n := range []int{1, 8, 64, 4096, 32768} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			bulker := NewBulker(&fixedTransport{body: []byte(`{}`)}, nil)
			queue := makeAPIKeyQueue(b, bulker, n)
			ctx := context.Background()
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				if err := bulker.flushUpdateAPIKey(ctx, queue); err != nil {
					b.Fatal(err)
				}
				drainQueue(queue)
			}
		})
	}
}
