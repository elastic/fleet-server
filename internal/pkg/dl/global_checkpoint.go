// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"

	"fleet/internal/pkg/bulk"
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

	Error bulk.ErrorT `json:"error,omitempty"`
}

// QueryGlobalCheckpoint returns index global checkpoint
func QueryGlobalCheckpoint(ctx context.Context, bulker bulk.Bulk, index string) (seqno int64, err error) {
	seqno = defaultSeqNo

	// Can't use the regular bulk search for _stats
	cli := bulker.Client()

	res, err := cli.Indices.Stats(
		cli.Indices.Stats.WithContext(ctx),
		cli.Indices.Stats.WithIndex(index),
		cli.Indices.Stats.WithLevel("shards"),
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
