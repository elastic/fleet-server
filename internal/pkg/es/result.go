// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package es

import (
	"encoding/json"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// Error
type ErrorT struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
	Cause  struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"caused_by"`
}

// Acknowledgement response
type AckResponse struct {
	Acknowledged bool            `json:"acknowledged"`
	Error        json.RawMessage `json:"error,omitempty"`
}

type HitT struct {
	ID      string          `json:"_id"`
	SeqNo   int64           `json:"_seq_no"`
	Version int64           `json:"version"`
	Index   string          `json:"_index"`
	Source  json.RawMessage `json:"_source"`
	Score   *float64        `json:"_score"`
	Fields  map[string]any  `json:"fields"`
}

func (hit *HitT) Unmarshal(v any) error {
	err := json.Unmarshal(hit.Source, v)
	if err != nil {
		return err
	}
	if s, ok := v.(model.ESInitializer); ok {
		s.ESInitialize(hit.ID, hit.SeqNo, hit.Version)
	}
	return nil
}

type HitsT struct {
	Hits  []HitT `json:"hits"`
	Total struct {
		Relation string `json:"relation"`
		Value    uint64 `json:"value"`
	} `json:"total"`
	MaxScore *float64 `json:"max_score"`
}

// Bucket is a generic aggregation bucket. Aggregations holds the hits of every
// top-hits style sub-aggregation found in the bucket, keyed by aggregation name.
type Bucket struct {
	Key          string           `json:"key"`
	DocCount     int64            `json:"doc_count"`
	Aggregations map[string]HitsT `json:"-"`
}

// Member names of an aggregation bucket handled by Bucket.UnmarshalJSON.
const (
	bucketKeyField      = "key"
	bucketDocCountField = "doc_count"
	bucketHitsField     = "hits"
)

// UnmarshalJSON decodes the bucket. The aggregation names are dynamic, so the
// bucket is first split into raw members. Each member that is an object with a
// "hits" member is then decoded straight into HitsT. HitT.Source is a
// json.RawMessage, so the (potentially large) _source documents are only copied
// and never decoded into an intermediate any tree, which is what the previous
// implementation did before marshaling the hits back to bytes.
//
// Note that Source now holds the bytes exactly as received. The previous
// implementation returned them re-marshaled: keys sorted, numbers round-tripped
// through float64 (integers above 2^53 lost precision) and <, > and & escaped.
// The decoded meaning is the same for any value float64 can represent.
func (b *Bucket) UnmarshalJSON(data []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	out := Bucket{Aggregations: make(map[string]HitsT)}
	for name, value := range members {
		switch name {
		case bucketKeyField:
			if err := json.Unmarshal(value, &out.Key); err != nil {
				return err
			}
			continue
		case bucketDocCountField:
			if err := json.Unmarshal(value, &out.DocCount); err != nil {
				return err
			}
			continue
		}
		// Skip anything that is not an object (numbers, strings, arrays, null).
		if len(value) == 0 || value[0] != '{' {
			continue
		}
		var agg map[string]json.RawMessage
		if err := json.Unmarshal(value, &agg); err != nil {
			return err
		}
		rawHits, ok := agg[bucketHitsField]
		if !ok {
			continue
		}
		var hits HitsT
		if err := json.Unmarshal(rawHits, &hits); err != nil {
			return err
		}
		out.Aggregations[name] = hits
	}
	*b = out
	return nil
}

type Aggregation struct {
	Value                   float64  `json:"value"`
	DocCountErrorUpperBound int64    `json:"doc_count_error_upper_bound"`
	SumOtherDocCount        int64    `json:"sum_other_doc_count"`
	Buckets                 []Bucket `json:"buckets,omitempty"`
}

type Response struct {
	Status   int    `json:"status"`
	Took     uint64 `json:"took"`
	TimedOut bool   `json:"timed_out"`
	Shards   struct {
		Total      uint64 `json:"total"`
		Successful uint64 `json:"successful"`
		Skipped    uint64 `json:"skipped"`
		Failed     uint64 `json:"failed"`
	} `json:"_shards"`
	Hits         HitsT                  `json:"hits"`
	Aggregations map[string]Aggregation `json:"aggregations,omitempty"`

	Error json.RawMessage `json:"error,omitempty"`
}

type DeleteByQueryResponse struct {
	Status   int    `json:"status"`
	Took     uint64 `json:"took"`
	TimedOut bool   `json:"timed_out"`
	Deleted  int64  `json:"deleted"`

	Error json.RawMessage `json:"error,omitempty"`
}

type ResultT struct {
	HitsT
	Aggregations map[string]Aggregation
}
