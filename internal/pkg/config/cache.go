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
	defaultAPIKeyTTL    = time.Minute * 15 // APIKey validation is a bottleneck.
	defaultAPIKeyJitter = time.Minute * 5  // Jitter allows some randomness on APIKeyTTL, zero to disable
)

type Cache struct {
	NumCounters  int64         `config:"num_counters"`
	MaxCost      int64         `config:"max_cost"`
	ActionTTL    time.Duration `config:"ttl_action"`
	EnrollKeyTTL time.Duration `config:"ttl_enroll_key"`
	ArtifactTTL  time.Duration `config:"ttl_artifact"`
	APIKeyTTL    time.Duration `config:"ttl_api_key"`
	APIKeyJitter time.Duration `config:"jitter_api_key"`
}

func (c *Cache) InitDefaults() {
	c.LoadLimits(loadLimits(0))
}

// LoadLimits loads envLimits for any attribute that is not defined in Cache
func (c *Cache) LoadLimits(limits *envLimits) {
	l := limits.Cache

	if c.NumCounters == 0 {
		c.NumCounters = l.NumCounters
	}
	if c.MaxCost == 0 {
		c.MaxCost = l.MaxCost
	}
	if c.ActionTTL == 0 {
		c.ActionTTL = defaultActionTTL
	}
	if c.EnrollKeyTTL == 0 {
		c.EnrollKeyTTL = defaultEnrollKeyTTL
	}
	if c.ArtifactTTL == 0 {
		c.ArtifactTTL = defaultArtifactTTL
	}
	if c.APIKeyTTL == 0 {
		c.APIKeyTTL = defaultAPIKeyTTL
	}
	if c.APIKeyJitter == 0 {
		c.APIKeyJitter = defaultAPIKeyJitter
	}
}
