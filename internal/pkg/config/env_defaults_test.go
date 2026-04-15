// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goyaml "gopkg.in/yaml.v3"
)

func TestLoadLimits(t *testing.T) {
	testCases := []struct {
		Name                 string
		ConfiguredAgentLimit int
		ExpectedAgentLimit   int
	}{
		{"default", -1, int(getMaxInt())},
		{"few agents", 5, 2500},
		{"512", 512, 2500},
		{"lesser bound", 5001, 10000},
		{"upper bound", 10000, 10000},
		{"above max", 40001, int(getMaxInt())},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			log := testlog.SetLogger(t)
			zerolog.DefaultContextLogger = &log
			l := loadLimits(&log, tc.ConfiguredAgentLimit)

			require.Equal(t, tc.ExpectedAgentLimit, l.Agents.Max)
		})
	}
}

func TestDefaultLimitsYAMLKeys(t *testing.T) {
	// Verify that all embedded YAML files have keys matching the Go struct tags.
	// A key typo (e.g. "pgp_retieval_limit" instead of "pgp_retrieval_limit")
	// causes the value to silently fall back to hardcoded defaults.
	validTags := make(map[string]bool)
	rt := reflect.TypeOf(serverLimitDefaults{})
	for i := 0; i < rt.NumField(); i++ {
		if tag := rt.Field(i).Tag.Get("config"); tag != "" {
			validTags[tag] = true
		}
	}

	require.NotEmpty(t, defaults, "embedded defaults should be loaded")
	err := fs.WalkDir(defaultsFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		name := strings.TrimSuffix(strings.TrimPrefix(path, "defaults/"), "_limits.yml")
		t.Run(name, func(t *testing.T) {
			f, err := defaultsFS.Open(path)
			require.NoError(t, err)
			data, err := io.ReadAll(f)
			require.NoError(t, err)

			var raw map[string]interface{}
			require.NoError(t, goyaml.Unmarshal(data, &raw))

			serverLimits, ok := raw["server_limits"].(map[string]interface{})
			require.True(t, ok, "server_limits key should exist in %s", path)

			for key := range serverLimits {
				assert.True(t, validTags[key],
					"YAML key %q in %s has no matching config struct tag on serverLimitDefaults", key, path)
			}
		})
		return nil
	})
	require.NoError(t, err)
}
