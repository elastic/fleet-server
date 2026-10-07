// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package es

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyBucket is a copy of the previous Bucket implementation, which decoded
// the whole bucket (including every _source) into any and marshaled the hits
// back to bytes before decoding them into HitsT. It is kept to check that the
// current implementation is equivalent.
type legacyBucket Bucket

type legacyBucketInner Bucket

func (b *legacyBucket) UnmarshalJSON(data []byte) error {
	b2 := legacyBucketInner{}
	err := json.Unmarshal(data, &b2)
	if err != nil {
		return err
	}
	var aggs map[string]any
	err = json.Unmarshal(data, &aggs)
	if err != nil {
		return err
	}
	delete(aggs, "key")
	delete(aggs, "doc_count")
	b2.Aggregations = make(map[string]HitsT)
	for name, value := range aggs {
		vMap, ok := value.(map[string]any)
		if !ok {
			continue
		}
		hMap, ok := vMap["hits"]
		if !ok {
			continue
		}
		data, err := json.Marshal(hMap)
		if err != nil {
			return err
		}
		var hits HitsT
		err = json.Unmarshal(data, &hits)
		if err != nil {
			return err
		}
		b2.Aggregations[name] = hits
	}
	*b = legacyBucket(b2)
	return nil
}

const (
	hitsEmpty    = `{"total":{"value":0,"relation":"eq"},"max_score":null,"hits":[]}`
	simpleSource = `{"policy_id":"p1","revision_idx":3,"data":{"a":[1,2,{"b":null}]}}`
)

func hitsWith(source string) string {
	return `{"total":{"value":1,"relation":"eq"},"max_score":1.5,"hits":[` +
		`{"_index":".fleet-policies-7","_id":"abc","_seq_no":42,"_score":1.5,"fields":{"f":[1,"x"]},"_source":` + source + `,"sort":[1]}]}`
}

// requireSameBucket asserts that both buckets have the same key, doc count and
// aggregations, comparing sources by their decoded meaning.
func requireSameBucket(t *testing.T, want legacyBucket, got Bucket) {
	t.Helper()
	require.Equal(t, want.Key, got.Key)
	require.Equal(t, want.DocCount, got.DocCount)
	require.NotNil(t, got.Aggregations)
	require.Len(t, got.Aggregations, len(want.Aggregations))
	for name, wantHits := range want.Aggregations {
		gotHits, ok := got.Aggregations[name]
		require.Truef(t, ok, "aggregation %q missing", name)
		assert.Equal(t, wantHits.Total, gotHits.Total, name)
		assert.Equal(t, wantHits.MaxScore, gotHits.MaxScore, name)
		require.Len(t, gotHits.Hits, len(wantHits.Hits), name)
		for i, wh := range wantHits.Hits {
			gh := gotHits.Hits[i]
			assert.Equal(t, wh.ID, gh.ID)
			assert.Equal(t, wh.Index, gh.Index)
			assert.Equal(t, wh.SeqNo, gh.SeqNo)
			assert.Equal(t, wh.Version, gh.Version)
			assert.Equal(t, wh.Score, gh.Score)
			assert.Equal(t, wh.Fields, gh.Fields)
			var ws, gs any
			require.NoError(t, json.Unmarshal(wh.Source, &ws))
			require.NoError(t, json.Unmarshal(gh.Source, &gs))
			assert.Equal(t, ws, gs)
		}
	}
}

func TestBucketUnmarshalEquivalentToLegacy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		aggs int
	}{
		{"realistic top hits", `{"key":"policy-1","doc_count":3,"latest":{"hits":` + hitsWith(simpleSource) + `}}`, 1},
		{"several aggregations", `{"key":"k","doc_count":2,"a":{"hits":` + hitsWith(simpleSource) + `},"b":{"hits":` + hitsEmpty + `},"c":{"hits":` + hitsWith(`{"x":1}`) + `}}`, 3},
		{"non object values", `{"key":"k","doc_count":1,"n":5,"s":"str","arr":[{"hits":1}],"nul":null,"t":true,"ok":{"hits":` + hitsEmpty + `}}`, 1},
		{"object without hits", `{"key":"k","doc_count":1,"o":{"value":3},"empty":{}}`, 0},
		{"empty hits", `{"key":"k","doc_count":0,"a":{"hits":` + hitsEmpty + `}}`, 1},
		{"null hits", `{"key":"k","doc_count":0,"a":{"hits":null}}`, 1},
		{"empty hits object", `{"key":"k","doc_count":0,"a":{"hits":{}}}`, 1},
		{"key and doc_count only", `{"key":"k","doc_count":7}`, 0},
		{"empty object", `{}`, 0},
		{"null bucket", `null`, 0},
		{"null key and doc_count", `{"key":null,"doc_count":null}`, 0},
		{"unknown members", `{"key":"k","doc_count":1,"unknown":{"x":[1,2,3]},"another":"v","a":{"hits":` + hitsWith(simpleSource) + `,"extra":1}}`, 1},
		{"nested and escapes", `{"key":"ké\n","doc_count":1,"a":{"hits":` + hitsWith(
			`{"s":"quote \" backslash \\ slash \/ tab \t nl \n","u":"é中😀 <b> & <>","emoji":"😀","nested":{"a":{"b":{"c":[[1,[2,[3]]],{"d":[]}]}}},"empty":{},"list":[],"f":1.5e3,"neg":-0.25,"big":1e20,"t":true,"n":null}`) + `}}`, 1},
		{"hit with source null", `{"key":"k","doc_count":1,"a":{"hits":{"total":{"value":1,"relation":"eq"},"hits":[{"_id":"x","_source":null}]}}}`, 1},
		{"multiple hits", `{"key":"k","doc_count":2,"a":{"hits":{"hits":[{"_id":"1","_source":{"a":1}},{"_id":"2","_source":{"a":2}}]}}}`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var want legacyBucket
			require.NoError(t, json.Unmarshal([]byte(tc.in), &want))
			var got Bucket
			require.NoError(t, json.Unmarshal([]byte(tc.in), &got))
			assert.Len(t, got.Aggregations, tc.aggs)
			requireSameBucket(t, want, got)
		})
	}
}

func TestBucketUnmarshalInSlice(t *testing.T) {
	in := `[{"key":"a","doc_count":1,"x":{"hits":` + hitsWith(simpleSource) + `}},{"key":"b","doc_count":2}]`
	var want []legacyBucket
	require.NoError(t, json.Unmarshal([]byte(in), &want))
	var got []Bucket
	require.NoError(t, json.Unmarshal([]byte(in), &got))
	require.Len(t, got, len(want))
	for i := range want {
		requireSameBucket(t, want[i], got[i])
	}
}

func TestBucketUnmarshalKeepsSourceBytes(t *testing.T) {
	// The previous implementation re-marshaled the source: keys were sorted and
	// numbers went through float64, so integers above 2^53 lost precision. The
	// new implementation hands over the source unchanged.
	sources := map[string]string{
		"integer above 2^53": `{"id":9007199254740993,"other":18446744073709551615}`,
		"unsorted keys":      `{"z":1,"a":2,"m":{"y":true,"b":false}}`,
		"html characters":    `{"s":"<b>&</b>"}`,
		"whitespace":         `{ "a" : 1 }`,
	}
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			in := `{"key":"k","doc_count":1,"a":{"hits":` + hitsWith(src) + `}}`

			var got Bucket
			require.NoError(t, json.Unmarshal([]byte(in), &got))
			require.Len(t, got.Aggregations["a"].Hits, 1)
			assert.Equal(t, src, string(got.Aggregations["a"].Hits[0].Source))

			var old legacyBucket
			require.NoError(t, json.Unmarshal([]byte(in), &old))
			require.Len(t, old.Aggregations["a"].Hits, 1)
			assert.NotEqual(t, src, string(old.Aggregations["a"].Hits[0].Source))
		})
	}
}

func TestBucketUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"truncated", `{"key":"k","doc_count":1`},
		{"not json", `not json`},
		{"trailing garbage", `{"key":"k"} x`},
		{"array", `[1,2]`},
		{"string", `"k"`},
		{"number", `5`},
		{"key is number", `{"key":5,"doc_count":1}`},
		{"key is object", `{"key":{},"doc_count":1}`},
		{"doc_count is string", `{"key":"k","doc_count":"1"}`},
		{"doc_count is float", `{"key":"k","doc_count":1.5}`},
		{"doc_count is object", `{"key":"k","doc_count":{}}`},
		{"hits is string", `{"key":"k","a":{"hits":"x"}}`},
		{"hits is array of numbers", `{"key":"k","a":{"hits":[1]}}`},
		{"hits.hits is object", `{"key":"k","a":{"hits":{"hits":{}}}}`},
		{"hit id is number", `{"key":"k","a":{"hits":{"hits":[{"_id":5}]}}}`},
		{"hit is not object", `{"key":"k","a":{"hits":{"hits":[1]}}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var want legacyBucket
			wantErr := json.Unmarshal([]byte(tc.in), &want)
			require.Error(t, wantErr, "legacy implementation must reject this input")

			var got Bucket
			require.Error(t, json.Unmarshal([]byte(tc.in), &got))
		})
	}
}
