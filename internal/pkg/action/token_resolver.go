// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package action

import (
	"context"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/dsl"

	lru "github.com/hashicorp/golang-lru"
	"github.com/rs/zerolog/log"
)

const cacheSize = 5000

type TokenResolver struct {
	bulker bulk.Bulk
	cache  *lru.Cache
	tmpl   *dsl.Tmpl
}

func NewTokenResolver(bulker bulk.Bulk) (*TokenResolver, error) {
	cache, err := lru.New(cacheSize)
	if err != nil {
		return nil, err
	}

	tmpl, err := dl.PrepareQuerySeqNoByDocId()
	return &TokenResolver{
		bulker: bulker,
		cache:  cache,
		tmpl:   tmpl,
	}, nil
}

func (r *TokenResolver) Resolve(ctx context.Context, token string) (seqno int64, err error) {
	if token == "" {
		return seqno, dl.ErrNotFound
	}
	if v, ok := r.cache.Get(token); ok {
		seqno = v.(int64)
		log.Debug().Str("token", token).Int64("seqno", seqno).Msg("Found token cached")
		return
	}

	seqno, err = dl.QuerySeqNoByDocId(ctx, r.bulker, r.tmpl, dl.FleetActions, token)
	if err != nil {
		return
	}

	r.cache.Add(token, seqno)

	return
}
