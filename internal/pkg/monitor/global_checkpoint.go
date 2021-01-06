// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

import (
	"context"
	"encoding/json"
	"fleet-server/internal/pkg/es"

	"github.com/elastic/go-elasticsearch/v8"
)

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

	if stats, ok := sres.IndexStats[index]; ok {
		if shards, ok := stats.Shards["0"]; ok {
			if len(shards) > 0 {
				seqno = shards[0].SeqNo.GlobalCheckpoint
			}
		}
	}

	return
}
