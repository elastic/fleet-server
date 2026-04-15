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

// TestDefaultLimitsYAML keys verifies that all embedded .yml files have keys that match go struct tags.
// A typo in a yml key, e.g. "pgp_retieval_limit" instead of "pgp_retrieval_limit" causes a test failure.
func TestDefaultLimitsYAMLKeys(t *testing.T) {
	rt := reflect.TypeOf(serverLimitDefaults{})
	validTags := make([]string, 0, rt.NumField())
	for field := range rt.Fields() {
		if tag := field.Tag.Get("config"); tag != "" {
			validTags = append(validTags, tag)
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

			var raw map[string]any
			require.NoError(t, goyaml.Unmarshal(data, &raw))

			require.Containsf(raw, "server_limits", "%s does not contain server_limits attribute", path)
			serverLimits, ok := raw["server_limits"].(map[string]any)
			require.Truef(t, ok, "server_limits in %s is not type map[string]any detected type: %T", path, raw["server_limits"])

			for key := range serverLimits {
				assert.Contains(t, validTags, key, "YAML key %q in %s has no matching config struct tag on serverLimitDefaults", key, path)
			}
		})
		return nil
	})
	require.NoError(t, err)
}
