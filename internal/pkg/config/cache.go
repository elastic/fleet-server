// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

const (
	defaultCacheNumCounters = 500000           // 10x times expected count
	defaultCacheMaxCost     = 50 * 1024 * 1024 // 50MiB cache size
)

type Cache struct {
	NumCounters int64 `config:"num_counters"`
	MaxCost     int64 `config:"max_cost"`
}

func (c *Cache) InitDefaults() {
	c.NumCounters = defaultCacheNumCounters
	c.MaxCost = defaultCacheMaxCost
}
