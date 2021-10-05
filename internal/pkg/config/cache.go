// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"time"
)

const (
	defaultActionTTL    = time.Minute * 5
	defaultEnrollKeyTTL = time.Minute
	defaultArtifactTTL  = time.Hour * 24
	defaultApiKeyTTL    = time.Minute * 15 // ApiKey validation is a bottleneck.
	defaultApiKeyJitter = time.Minute * 5  // Jitter allows some randomness on ApiKeyTTL, zero to disable
)

type Cache struct {
	NumCounters  int64         `config:"num_counters"`
	MaxCost      int64         `config:"max_cost"`
	ActionTTL    time.Duration `config:"ttl_action"`
	EnrollKeyTTL time.Duration `config:"ttl_enroll_key"`
	ArtifactTTL  time.Duration `config:"ttl_artifact"`
	ApiKeyTTL    time.Duration `config:"ttl_api_key"`
	ApiKeyJitter time.Duration `config:"jitter_api_key"`
}

func (c *Cache) InitDefaults() {
	l := loadLimits().Cache

	c.NumCounters = l.NumCounters
	c.MaxCost = l.MaxCost
	c.ActionTTL = defaultActionTTL
	c.EnrollKeyTTL = defaultEnrollKeyTTL
	c.ArtifactTTL = defaultArtifactTTL
	c.ApiKeyTTL = defaultApiKeyTTL
	c.ApiKeyJitter = defaultApiKeyJitter
}
