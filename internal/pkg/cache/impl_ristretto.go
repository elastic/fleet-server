// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package cache

import (
	"github.com/dgraph-io/ristretto"
)

func newCache(cfg Config) (Cacher, error) {
	rcfg := &ristretto.Config{
		NumCounters: cfg.NumCounters,
		MaxCost:     cfg.MaxCost,
		BufferItems: 64,
	}

	return ristretto.NewCache(rcfg)
}
