// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package action

import (
	"context"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog/log"
)

const cacheSize = 5000

// TokenResolver is an LRU cache for seqno on agent check-in.
// A token is the elasticsearch document_id (not a SeqNo). It is used
// by fleet-server to send state information to the agent.
type TokenResolver struct {
	bulker bulk.Bulk
	cache  *lru.Cache[string, int64]
}

// NewTokenResolver returns a TokenResolver that uses the Bulk to resolve the returned seqno on a cache miss.
func NewTokenResolver(bulker bulk.Bulk) (*TokenResolver, error) {
	cache, err := lru.New[string, int64](cacheSize)
	if err != nil {
		return nil, err
	}

	return &TokenResolver{
		bulker: bulker,
		cache:  cache,
	}, nil
}

// Resolve will return the seqno from the cache or retrieve and cache it using its bulk.Bulk.
func (r *TokenResolver) Resolve(ctx context.Context, token string) (int64, error) {
	if token == "" {
		return 0, dl.ErrNotFound
	}
	if v, ok := r.cache.Get(token); ok {
		log.Debug().Str("token", token).Int64("seqno", v).Msg("Found token cached")
		return v, nil
	}

	seqno, err := dl.FindSeqNoByDocID(ctx, r.bulker, dl.QuerySeqNoByDocID, dl.FleetActions, token)
	if err != nil {
		return seqno, err
	}

	r.cache.Add(token, seqno)

	return seqno, nil
}
