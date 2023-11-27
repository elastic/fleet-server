// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"time"

	"github.com/rs/zerolog"
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

func (c *Cache) InitDefaults() {}

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

// CopyCache returns a copy of the config's Cache settings
func CopyCache(cfg *Config) Cache {
	ccfg := cfg.Inputs[0].Cache
	return Cache{
		NumCounters:  ccfg.NumCounters,
		MaxCost:      ccfg.MaxCost,
		ActionTTL:    ccfg.ActionTTL,
		EnrollKeyTTL: ccfg.EnrollKeyTTL,
		ArtifactTTL:  ccfg.ArtifactTTL,
		APIKeyTTL:    ccfg.APIKeyTTL,
		APIKeyJitter: ccfg.APIKeyJitter,
	}
}

// MarshalZerologObject turns the cache settings into a zerolog event
func (c *Cache) MarshalZerologObject(e *zerolog.Event) {
	e.Int64("numCounters", c.NumCounters)
	e.Int64("maxCost", c.MaxCost)
	e.Dur("actionTTL", c.ActionTTL)
	e.Dur("enrollTTL", c.EnrollKeyTTL)
	e.Dur("artifactTTL", c.ArtifactTTL)
	e.Dur("apiKeyTTL", c.APIKeyTTL)
	e.Dur("apiKeyJitter", c.APIKeyJitter)
}
