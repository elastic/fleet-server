// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package cache

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidAPIKeyDisabledKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := config.Cache{
			NumCounters: 100,
			MaxCost:     100000,
			APIKeyTTL:   5 * time.Minute,
		}
		c, err := New(cfg)
		require.NoError(t, err)
		defer c.cache.Close() // stop ristretto background goroutines before bubble exits

		key := APIKey{ID: "test-id", Key: "test-key"}

		c.SetAPIKey(key, false)
		synctest.Wait()

		assert.False(t, c.ValidAPIKey(key), "disabled API key should not be valid")
	})
}

func TestValidAPIKeyEnabledKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := config.Cache{
			NumCounters: 100,
			MaxCost:     100000,
			APIKeyTTL:   5 * time.Minute,
		}
		c, err := New(cfg)
		require.NoError(t, err)
		defer c.cache.Close()

		key := APIKey{ID: "test-id", Key: "test-key"}

		c.SetAPIKey(key, true)
		synctest.Wait()

		assert.True(t, c.ValidAPIKey(key), "enabled API key with matching key should be valid")

		wrongKey := APIKey{ID: "test-id", Key: "wrong-key"}
		assert.False(t, c.ValidAPIKey(wrongKey), "API key with mismatched key value should not be valid")
	})
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

	assert.False(t, c.ValidAPIKey(key), "API key not in cache should not be valid")
}
