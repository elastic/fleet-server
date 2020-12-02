// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"encoding/json"
	"errors"
	"fmt"
)

type BulkIndexerResponse struct {
	Took      int                                  `json:"took"`
	HasErrors bool                                 `json:"errors"`
	Items     []map[string]BulkIndexerResponseItem `json:"items,omitempty"`
}

// Comment out fields we don't use; no point decoding.
type BulkIndexerResponseItem struct {
	//	Index      string `json:"_index"`
	DocumentID string `json:"_id"`
	//	Version    int64  `json:"_version"`
	//	Result     string `json:"result"`
	Status int `json:"status"`
	//	SeqNo      int64  `json:"_seq_no"`
	//	PrimTerm   int64  `json:"_primary_term"`

	//	Shards struct {
	//		Total      int `json:"total"`
	//		Successful int `json:"successful"`
	//		Failed     int `json:"failed"`
	//	} `json:"_shards"`

	Error struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
		Cause  struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"caused_by"`
	} `json:"error,omitempty"`
}

type MgetResponse struct {
	Items []MgetResponseItem `json:"docs"`
}

// Comment out fields we don't use; no point decoding.
type MgetResponseItem struct {
	//	Index      string          `json:"_index"`
	//	Type       string          `json:"_type"`
	//	DocumentID string          `json:"_id"`
	//	Version    int64           `json:"_version"`
	//	SeqNo      int64           `json:"_seq_no"`
	//	PrimTerm   int64           `json:"_primary_term"`
	Found bool `json:"found"`
	//	Routing    string          `json:"_routing"`
	Source json.RawMessage `json:"_source"`
	//	Fields     json.RawMessage `json:"_fields"`
}

func (i *MgetResponseItem) deriveError() error {
	if !i.Found {
		return ErrElasticNotFound
	}
	return nil
}

type HitT struct {
	Id     string          `json:"_id"`
	Index  string          `json:"_index"`
	Source json.RawMessage `json:"_source"`
	Score  *float64        `json:"_score"`
}

type HitsT struct {
	Hits  []HitT `json:"hits"`
	Total struct {
		Relation string `json:"relation"`
		Value    uint64 `json:"value"`
	} `json:"total"`
	MaxScore *float64 `json:"max_score"`
}

type MsearchResponseItem struct {
	Status   int    `json:"status"`
	Took     uint64 `json:"took"`
	TimedOut bool   `json:"timed_out"`
	Shards   struct {
		Total      uint64 `json:"total"`
		Successful uint64 `json:"successful"`
		Skipped    uint64 `json:"skipped"`
		Failed     uint64 `json:"failed"`
	} `json:"_shards"`
	Hits HitsT `json:"hits"`

	Error struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
		Cause  struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"caused_by"`
	} `json:"error,omitempty"`
}

type MsearchResponse struct {
	Responses []MsearchResponseItem `json:"responses"`
	Took      int                   `json:"took"`
}

type ErrElastic struct {
	Status int
	Type   string
	Reason string
	Cause  struct {
		Type   string
		Reason string
	}
}

func (e ErrElastic) Error() string {
	return fmt.Sprintf("Elastic fail %d:%s:%s", e.Status, e.Type, e.Reason)
}

var (
	ErrElasticVersionConflict = errors.New("elastic version conflict")
	ErrElasticNotFound        = errors.New("elastic not found")
	ErrInvalidBody            = errors.New("invalid body")
)

func (b *BulkIndexerResponseItem) deriveError() error {
	if b.Status == 200 || b.Status == 201 {
		return nil
	}

	var err error
	switch b.Error.Type {
	case "version_conflict_engine_exception":
		err = ErrElasticVersionConflict
	default:
		err = ErrElastic{
			Status: b.Status,
			Type:   b.Error.Type,
			Reason: b.Error.Reason,
			Cause: struct {
				Type   string
				Reason string
			}{
				b.Error.Cause.Type,
				b.Error.Cause.Reason,
			},
		}
	}

	return err
}

func (b *MsearchResponseItem) deriveError() error {
	if b.Status == 200 {
		return nil
	}

	var err error
	switch b.Error.Type {
	case "version_conflict_engine_exception":
		err = ErrElasticVersionConflict
	default:
		err = ErrElastic{
			Status: b.Status,
			Type:   b.Error.Type,
			Reason: b.Error.Reason,
			Cause: struct {
				Type   string
				Reason string
			}{
				b.Error.Cause.Type,
				b.Error.Cause.Reason,
			},
		}
	}

	return err
}
