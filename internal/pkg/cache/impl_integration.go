// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package cache

import (
	"time"
)

func newCache(_ Config) (Cacher, error) {
	return &NoCache{}, nil
}

type NoCache struct{}

func (c *NoCache) Get(_ interface{}) (interface{}, bool) {
	return nil, false
}

func (c *NoCache) Set(_ interface{}, _ interface{}, _ int64) bool {
	return true
}

func (c *NoCache) SetWithTTL(_, _ interface{}, _ int64, _ time.Duration) bool {
	return true
}

func (c *NoCache) Close() {
}
