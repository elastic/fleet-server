// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"encoding/json"
	"fleet-server/internal/pkg/model"
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
	Acknowledged bool   `json:"acknowledged"`
	Error        ErrorT `json:"error,omitempty"`
}

type HitT struct {
	Id      string          `json:"_id"`
	SeqNo   int64           `json:"_seq_no"`
	Version int64           `json:"version"`
	Index   string          `json:"_index"`
	Source  json.RawMessage `json:"_source"`
	Score   *float64        `json:"_score"`
}

func (hit *HitT) Unmarshal(v interface{}) error {
	err := json.Unmarshal(hit.Source, v)
	if err != nil {
		return err
	}
	if s, ok := v.(model.ESInitializer); ok {
		s.ESInitialize(hit.Id, hit.SeqNo, hit.Version)
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

type Bucket struct {
	// any fields added here with json tags must also be added to the
	// delete calls in the `UnmarshalJSON` function below
	Key          string           `json:"key"`
	DocCount     int64            `json:"doc_count"`
	Aggregations map[string]HitsT `json:"-"`
}

type _bucket Bucket

func (b *Bucket) UnmarshalJSON(data []byte) error {
	b2 := _bucket{}
	err := json.Unmarshal(data, &b2)
	if err != nil {
		return err
	}
	var aggs map[string]interface{}
	err = json.Unmarshal(data, &aggs)
	if err != nil {
		return err
	}
	// remove the json keys that already unmarshalled into the
	// bucket. this needs to stay in sync with the json tags
	// from `Bucket`.
	delete(aggs, "key")
	delete(aggs, "doc_count")
	b2.Aggregations = make(map[string]HitsT)
	for name, value := range aggs {
		vMap, ok := value.(map[string]interface{})
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
	*b = Bucket(b2)
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

	Error ErrorT `json:"error,omitempty"`
}

type ResultT struct {
	HitsT
	Aggregations map[string]Aggregation
}
