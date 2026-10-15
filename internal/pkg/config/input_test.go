// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package config

import (
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/elastic/go-ucfg/yaml"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBindAddress(t *testing.T) {
	testcases := map[string]struct {
		cfg    Server
		result string
	}{
		"localhost": {
			cfg: Server{
				Host: "localhost",
				Port: 5000,
			},
			result: "localhost:5000",
		},
		"ipv6": {
			cfg: Server{
				Host: "::1",
				Port: 6565,
			},
			result: "[::1]:6565",
		},
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			_ = testlog.SetLogger(t)
			res := test.cfg.BindAddress()
			if !assert.True(t, cmp.Equal(test.result, res)) {
				diff := cmp.Diff(test.result, res)
				if diff != "" {
					t.Errorf("%s mismatch (-want +got):\n%s", name, diff)
				}
			}
		})
	}
}

func TestFeatureFlagsValidate(t *testing.T) {
	t.Run("empty max agent version is valid", func(t *testing.T) {
		require.NoError(t, (&FeatureFlags{}).Validate())
	})
	t.Run("minor max agent version is valid", func(t *testing.T) {
		require.NoError(t, (&FeatureFlags{MaxAgentVersion: "9.6"}).Validate())
	})
	t.Run("full max agent version is valid", func(t *testing.T) {
		require.NoError(t, (&FeatureFlags{MaxAgentVersion: "9.6.1"}).Validate())
	})
	t.Run("malformed max agent version is rejected", func(t *testing.T) {
		require.Error(t, (&FeatureFlags{MaxAgentVersion: "9.six"}).Validate())
	})
}

func TestMaxAgentVersionParse(t *testing.T) {
	load := func(t *testing.T, value string) string {
		t.Helper()
		c, err := yaml.NewConfig([]byte("feature_flags:\n  _max_agent_version: "+value+"\n"), DefaultOptions...)
		require.NoError(t, err)
		var srv Server
		require.NoError(t, c.Unpack(&srv, DefaultOptions...))
		return srv.Features.MaxAgentVersion
	}

	t.Run("quoted", func(t *testing.T) {
		require.Equal(t, "9.10", load(t, `"9.10"`))
	})
	// An unquoted YAML float loses its trailing zero when unpacked into the string field, so 9.10 is
	// read as 9.1. This is why the value must be quoted; the test pins the behavior.
	t.Run("unquoted float loses trailing zero", func(t *testing.T) {
		require.Equal(t, "9.1", load(t, `9.10`))
	})
}

func TestServerBulkValidate(t *testing.T) {
	t.Run("rejects negative FlushMaxPending", func(t *testing.T) {
		cfg := ServerBulk{}
		cfg.InitDefaults()
		cfg.FlushMaxPending = -1
		require.Error(t, cfg.Validate())
	})
	t.Run("rejects zero FlushMaxPending", func(t *testing.T) {
		cfg := ServerBulk{}
		cfg.InitDefaults()
		cfg.FlushMaxPending = 0
		require.Error(t, cfg.Validate())
	})
	t.Run("accepts positive FlushMaxPending", func(t *testing.T) {
		cfg := ServerBulk{}
		cfg.InitDefaults()
		require.NoError(t, cfg.Validate())
	})
}
