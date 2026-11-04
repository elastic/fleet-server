// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"errors"
	"fmt"
	"time"
)

const (
	defaultFeatureFlagsPollInterval           = 10 * time.Second
	defaultFeatureFlagsPollOverlap            = 60 * time.Second
	defaultFeatureFlagsResyncInterval         = time.Hour
	defaultFeatureFlagsDefinitionsIndex       = ".feature-flags-definitions"
	defaultFeatureFlagsObservedContextsIndex  = ".feature-flags-observed-contexts"
	defaultObservedContextsFlushInterval      = 30 * time.Second
	defaultObservedContextsMaxNewPerFlush     = 10000
	defaultObservedContextsLastSeenResolution = time.Hour

	minFeatureFlagsPollInterval  = time.Second
	minObservedContextsFlushTime = time.Second
)

// FeatureFlagsService is the configuration of the feature flags (OFREP) service.
// It is not related to Server.Features, which holds Fleet Server's own internal toggles.
type FeatureFlagsService struct {
	// Enabled turns on the OFREP endpoints and the definitions sync. Disabled by default.
	Enabled bool `config:"enabled"`
	// PollInterval is how often the definitions index is polled for changes.
	PollInterval time.Duration `config:"poll_interval"`
	// PollOverlap is subtracted from the last successful poll start to absorb refresh delay and clock skew.
	PollOverlap time.Duration `config:"poll_overlap"`
	// ResyncInterval is how often an unconditional full reload of the definitions is done.
	ResyncInterval time.Duration `config:"resync_interval"`
	// DefinitionsIndex is the index holding environments, apps, credentials and flags.
	DefinitionsIndex string `config:"definitions_index"`
	// ObservedContextsIndex is the index the observed evaluation contexts are written to.
	ObservedContextsIndex string                  `config:"observed_contexts_index"`
	CORS                  FeatureFlagsCORS        `config:"cors"`
	ObservedContexts      ObservedContextsService `config:"observed_contexts"`
}

// FeatureFlagsCORS configures CORS for the OFREP endpoints, needed by browser SDKs.
type FeatureFlagsCORS struct {
	// AllowedOrigins lists the origins allowed to call the OFREP endpoints. "*" allows any origin.
	AllowedOrigins []string `config:"allowed_origins"`
}

// ObservedContextsService configures the collection of evaluation contexts seen by the OFREP endpoints.
type ObservedContextsService struct {
	Enabled bool `config:"enabled"`
	// FlushInterval is how often the collected contexts are written to Elasticsearch.
	FlushInterval time.Duration `config:"flush_interval"`
	// MaxNewContextsPerFlush caps how many previously unseen contexts are written per app and environment per flush.
	MaxNewContextsPerFlush int `config:"max_new_contexts_per_flush"`
	// LastSeenResolution is the minimum movement of last_seen before a known context is written again.
	LastSeenResolution time.Duration `config:"last_seen_resolution"`
	// ExcludeAttributes lists context attributes (dotted keys) that are never stored.
	ExcludeAttributes []string `config:"exclude_attributes"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *FeatureFlagsService) InitDefaults() {
	c.Enabled = false
	c.PollInterval = defaultFeatureFlagsPollInterval
	c.PollOverlap = defaultFeatureFlagsPollOverlap
	c.ResyncInterval = defaultFeatureFlagsResyncInterval
	c.DefinitionsIndex = defaultFeatureFlagsDefinitionsIndex
	c.ObservedContextsIndex = defaultFeatureFlagsObservedContextsIndex
	c.CORS.AllowedOrigins = nil
	c.ObservedContexts.InitDefaults()
}

// Validate ensures that the configuration is valid.
func (c *FeatureFlagsService) Validate() error {
	if c.PollInterval < minFeatureFlagsPollInterval {
		return fmt.Errorf("feature_flags_service.poll_interval must be at least %s, got %s", minFeatureFlagsPollInterval, c.PollInterval)
	}
	if c.PollOverlap < 0 {
		return fmt.Errorf("feature_flags_service.poll_overlap must not be negative, got %s", c.PollOverlap)
	}
	if c.ResyncInterval < c.PollInterval {
		return fmt.Errorf("feature_flags_service.resync_interval (%s) must not be lower than poll_interval (%s)", c.ResyncInterval, c.PollInterval)
	}
	if c.DefinitionsIndex == "" {
		return errors.New("feature_flags_service.definitions_index must not be empty")
	}
	if c.ObservedContextsIndex == "" {
		return errors.New("feature_flags_service.observed_contexts_index must not be empty")
	}
	return c.ObservedContexts.Validate()
}

// InitDefaults initializes the defaults for the configuration.
func (c *ObservedContextsService) InitDefaults() {
	c.Enabled = false
	c.FlushInterval = defaultObservedContextsFlushInterval
	c.MaxNewContextsPerFlush = defaultObservedContextsMaxNewPerFlush
	c.LastSeenResolution = defaultObservedContextsLastSeenResolution
	c.ExcludeAttributes = nil
}

// Validate ensures that the configuration is valid.
func (c *ObservedContextsService) Validate() error {
	if c.FlushInterval < minObservedContextsFlushTime {
		return fmt.Errorf("feature_flags_service.observed_contexts.flush_interval must be at least %s, got %s", minObservedContextsFlushTime, c.FlushInterval)
	}
	if c.MaxNewContextsPerFlush <= 0 {
		return fmt.Errorf("feature_flags_service.observed_contexts.max_new_contexts_per_flush must be positive, got %d", c.MaxNewContextsPerFlush)
	}
	if c.LastSeenResolution < 0 {
		return fmt.Errorf("feature_flags_service.observed_contexts.last_seen_resolution must not be negative, got %s", c.LastSeenResolution)
	}
	return nil
}
