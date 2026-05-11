// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cache

import (
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidAPIKeyDisabledKey(t *testing.T) {
	cfg := config.Cache{
		NumCounters: 100,
		MaxCost:     100000,
		APIKeyTTL:   5 * time.Minute,
	}
	c, err := New(cfg)
	require.NoError(t, err)

	key := APIKey{ID: "test-id", Key: "test-key"}

	// Cache the key as disabled
	c.SetAPIKey(key, false)
	// ristretto is async; wait for value to be available
	time.Sleep(10 * time.Millisecond)

	// A disabled key must not be considered valid
	assert.False(t, c.ValidAPIKey(key), "disabled API key should not be valid")
}

func TestValidAPIKeyEnabledKey(t *testing.T) {
	cfg := config.Cache{
		NumCounters: 100,
		MaxCost:     100000,
		APIKeyTTL:   5 * time.Minute,
	}
	c, err := New(cfg)
	require.NoError(t, err)

	key := APIKey{ID: "test-id", Key: "test-key"}

	// Cache the key as enabled
	c.SetAPIKey(key, true)
	time.Sleep(10 * time.Millisecond)

	// Matching key should be valid
	assert.True(t, c.ValidAPIKey(key), "enabled API key with matching key should be valid")

	// Wrong key value should not be valid
	wrongKey := APIKey{ID: "test-id", Key: "wrong-key"}
	assert.False(t, c.ValidAPIKey(wrongKey), "API key with mismatched key value should not be valid")
}

func TestValidAPIKeyMiss(t *testing.T) {
	cfg := config.Cache{
		NumCounters: 100,
		MaxCost:     100000,
		APIKeyTTL:   5 * time.Minute,
	}
	c, err := New(cfg)
	require.NoError(t, err)

	key := APIKey{ID: "nonexistent", Key: "test-key"}

	// Key not in cache should not be valid
	assert.False(t, c.ValidAPIKey(key), "API key not in cache should not be valid")
}
