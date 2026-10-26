// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package config

import (
	"testing"
	"time"

	"github.com/elastic/go-ucfg/yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadFeatureFlagsServiceInput(t *testing.T, raw string) (Input, error) {
	t.Helper()
	c, err := yaml.NewConfig([]byte("type: fleet-server\n"+raw), DefaultOptions...)
	require.NoError(t, err)
	var in Input
	err = c.Unpack(&in, DefaultOptions...)
	return in, err
}

func TestFeatureFlagsServiceDefaults(t *testing.T) {
	in, err := loadFeatureFlagsServiceInput(t, "")
	require.NoError(t, err)

	ffs := in.FeatureFlagsService
	assert.False(t, ffs.Enabled)
	assert.Equal(t, 10*time.Second, ffs.PollInterval)
	assert.Equal(t, 60*time.Second, ffs.PollOverlap)
	assert.Equal(t, time.Hour, ffs.ResyncInterval)
	assert.Equal(t, ".feature-flags-definitions", ffs.DefinitionsIndex)
	assert.Equal(t, ".feature-flags-observed-contexts", ffs.ObservedContextsIndex)
	assert.Empty(t, ffs.CORS.AllowedOrigins)
	assert.False(t, ffs.ObservedContexts.Enabled)
	assert.Equal(t, 60*time.Second, ffs.ObservedContexts.FlushInterval)
	assert.Equal(t, 1000, ffs.ObservedContexts.MaxNewContextsPerFlush)
	assert.Equal(t, time.Hour, ffs.ObservedContexts.LastSeenResolution)
	assert.Empty(t, ffs.ObservedContexts.ExcludeAttributes)

	// The unrelated internal toggles keep their own defaults.
	assert.True(t, in.Server.Features.EnableOpAMP)
}

func TestFeatureFlagsServiceParse(t *testing.T) {
	in, err := loadFeatureFlagsServiceInput(t, `
feature_flags_service:
  enabled: true
  poll_interval: 5s
  poll_overlap: 30s
  resync_interval: 30m
  definitions_index: .ff-defs
  observed_contexts_index: .ff-observed
  cors:
    allowed_origins: ["https://kibana.example.com"]
  observed_contexts:
    enabled: true
    flush_interval: 10s
    max_new_contexts_per_flush: 50
    last_seen_resolution: 5m
    exclude_attributes: ["user.email"]
`)
	require.NoError(t, err)

	assert.Equal(t, FeatureFlagsService{
		Enabled:               true,
		PollInterval:          5 * time.Second,
		PollOverlap:           30 * time.Second,
		ResyncInterval:        30 * time.Minute,
		DefinitionsIndex:      ".ff-defs",
		ObservedContextsIndex: ".ff-observed",
		CORS:                  FeatureFlagsCORS{AllowedOrigins: []string{"https://kibana.example.com"}},
		ObservedContexts: ObservedContextsService{
			Enabled:                true,
			FlushInterval:          10 * time.Second,
			MaxNewContextsPerFlush: 50,
			LastSeenResolution:     5 * time.Minute,
			ExcludeAttributes:      []string{"user.email"},
		},
	}, in.FeatureFlagsService)
}

func TestFeatureFlagsServiceValidate(t *testing.T) {
	testcases := map[string]struct {
		raw string
		err string
	}{
		"poll interval too low": {
			raw: "feature_flags_service.poll_interval: 500ms",
			err: "poll_interval must be at least 1s",
		},
		"negative overlap": {
			raw: "feature_flags_service.poll_overlap: -1s",
			err: "poll_overlap must not be negative",
		},
		"resync lower than poll": {
			raw: "feature_flags_service:\n  poll_interval: 20s\n  resync_interval: 10s",
			err: "resync_interval (10s) must not be lower than poll_interval (20s)",
		},
		"empty definitions index": {
			raw: `feature_flags_service.definitions_index: ""`,
			err: "definitions_index must not be empty",
		},
		"empty observed contexts index": {
			raw: `feature_flags_service.observed_contexts_index: ""`,
			err: "observed_contexts_index must not be empty",
		},
		"flush interval too low": {
			raw: "feature_flags_service.observed_contexts.flush_interval: 100ms",
			err: "flush_interval must be at least 1s",
		},
		"max new contexts not positive": {
			raw: "feature_flags_service.observed_contexts.max_new_contexts_per_flush: 0",
			err: "max_new_contexts_per_flush must be positive",
		},
		"negative last seen resolution": {
			raw: "feature_flags_service.observed_contexts.last_seen_resolution: -1m",
			err: "last_seen_resolution must not be negative",
		},
	}
	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			_, err := loadFeatureFlagsServiceInput(t, tc.raw)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.err)
		})
	}
}

func TestOFREPLimitDefaults(t *testing.T) {
	limits := generateServerLimits(0)
	assert.Equal(t, defaultOFREPInterval, limits.OFREPLimit.Interval)
	assert.Equal(t, defaultOFREPBurst, limits.OFREPLimit.Burst)
	assert.Equal(t, int64(defaultOFREPMaxBody), limits.OFREPLimit.MaxBody)

	bad := ServerLimits{OFREPLimit: Limit{Max: -1}}
	require.ErrorContains(t, bad.Validate(), "ofrep_limit.max must not be negative")
}
