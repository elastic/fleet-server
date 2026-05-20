// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package cache

import (
	"github.com/dgraph-io/ristretto"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
)

func newCache(cfg config.Cache) (Cacher, error) {
	rcfg := &ristretto.Config{
		NumCounters: cfg.NumCounters,
		MaxCost:     cfg.MaxCost,
		BufferItems: 64,
	}

	return ristretto.NewCache(rcfg)
}
