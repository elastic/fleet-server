// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"

	"github.com/elastic/go-elasticsearch/v8"
)

var ErrGlobalCheckpoint = errors.New("global checkpoint error")

type shard struct {
	SeqNo struct {
		GlobalCheckpoint int64 `json:"global_checkpoint"`
	} `json:"seq_no"`
}

type indexStats struct {
	Shards map[string][]shard `json:"shards"`
}

type statsResponse struct {
	IndexStats map[string]indexStats `json:"indices"`

	Error es.ErrorT `json:"error,omitempty"`
}

func queryGlobalCheckpoint(ctx context.Context, es *elasticsearch.Client, index string) (seqno int64, err error) {
	seqno = defaultSeqNo

	res, err := es.Indices.Stats(
		es.Indices.Stats.WithContext(ctx),
		es.Indices.Stats.WithIndex(index),
		es.Indices.Stats.WithLevel("shards"),
	)

	if err != nil {
		return
	}

	defer res.Body.Close()

	var sres statsResponse
	err = json.NewDecoder(res.Body).Decode(&sres)
	if err != nil {
		return
	}

	if len(sres.IndexStats) > 1 {
		indices := make([]string, 0, len(sres.IndexStats))
		for k := range sres.IndexStats {
			indices = append(indices, k)
		}
		return seqno, fmt.Errorf("more than one indices found %v, %w", indices, ErrGlobalCheckpoint)
	}

	if len(sres.IndexStats) > 0 {
		// Grab the first and only index stats
		var stats indexStats
		for _, stats = range sres.IndexStats {
			break
		}

		if shards, ok := stats.Shards["0"]; ok {
			if len(shards) > 0 {
				seqno = shards[0].SeqNo.GlobalCheckpoint
			}
		}
	}

	return
}
