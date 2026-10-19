// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package es

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

const (
	benchBuckets    = 100
	benchSourceSize = 220 * 1024
)

// benchSource builds a deterministic JSON document of at least size bytes made
// of nested maps, arrays and strings.
func benchSource(seed, size int) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"policy_id":"policy-`)
	fmt.Fprintf(&buf, "%d", seed)
	buf.WriteString(`","revision_idx":`)
	fmt.Fprintf(&buf, "%d", seed%7+1)
	buf.WriteString(`,"data":{"inputs":[`)
	for i := 0; buf.Len() < size; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf,
			`{"id":"input-%d-%d","type":"logfile","enabled":true,"meta":{"package":{"name":"pkg-%d","version":"1.%d.0"}},`+
				`"streams":[{"paths":["/var/log/app-%d/*.log","/var/log/app-%d/*.json"],"processors":[{"add_fields":{"target":"data_stream","fields":{"dataset":"ds.%d","namespace":"default"}}}],"tags":["a","b","c"],"ratio":%d.5}],`+
				`"description":"line %d of the synthetic policy, with an escape \" and a unicode char \u00e9"}`,
			seed, i, i%13, i%5, i, i, i, i%100, i)
	}
	buf.WriteString(`]}}`)
	return buf.Bytes()
}

// benchBucketsJSON builds the JSON array of buckets, each holding one top-hits
// aggregation with a single large _source.
func benchBucketsJSON(tb testing.TB) []byte {
	tb.Helper()
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i := range benchBuckets {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, `{"key":"policy-%d","doc_count":1,"latest":{"hits":{"total":{"value":1,"relation":"eq"},"max_score":null,"hits":[{"_index":".fleet-policies-7","_id":"doc-%d","_seq_no":%d,"_score":null,"_source":`, i, i, i)
		buf.Write(benchSource(i, benchSourceSize))
		buf.WriteString(`}]}}}`)
	}
	buf.WriteByte(']')
	if !json.Valid(buf.Bytes()) {
		tb.Fatal("benchmark fixture is not valid JSON")
	}
	return buf.Bytes()
}

func BenchmarkBucketUnmarshal(b *testing.B) {
	data := benchBucketsJSON(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		var out []Bucket
		if err := json.Unmarshal(data, &out); err != nil {
			b.Fatal(err)
		}
		if len(out) != benchBuckets {
			b.Fatalf("unexpected number of buckets: %d", len(out))
		}
	}
}
