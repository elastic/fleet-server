// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package config

import (
	"fmt"
	"path/filepath"
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	fleetversion "github.com/elastic/fleet-server/v7/version"

	"github.com/elastic/go-ucfg/yaml"
	"github.com/google/go-cmp/cmp"
	goversion "github.com/hashicorp/go-version"
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

func loadMaxAgentVersion(value string) (AgentVersionLimit, error) {
	c, err := yaml.NewConfig([]byte("feature_flags:\n  _max_agent_version: "+value+"\n"), DefaultOptions...)
	if err != nil {
		return "", err
	}
	var srv Server
	if err := c.Unpack(&srv, DefaultOptions...); err != nil {
		return "", err
	}
	return srv.Features.MaxAgentVersion, nil
}

func TestMaxAgentVersionParse(t *testing.T) {
	higherMajor := fmt.Sprintf("%q", fmt.Sprintf("%d.0", builtinMajor(t)+1))

	valid := map[string]AgentVersionLimit{
		`"9.10"`: "9.10",
		`"9.6"`:  "9.6",
		`"8.19"`: "8.19",
		`""`:     "",
	}
	for in, want := range valid {
		t.Run("valid "+in, func(t *testing.T) {
			got, err := loadMaxAgentVersion(in)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	invalid := map[string]string{
		`9.10`:           "quoted string",
		`9`:              "quoted string",
		`true`:           "quoted string",
		`"9.6.1"`:        "MAJOR.MINOR",
		`"v9.6"`:         "MAJOR.MINOR",
		`"9.6-SNAPSHOT"`: "MAJOR.MINOR",
		`"9.six"`:        "MAJOR.MINOR",
		`"09.6"`:         "MAJOR.MINOR",
		`"9"`:            "MAJOR.MINOR",
		higherMajor:      "higher major version",
	}
	for in, msg := range invalid {
		t.Run("invalid "+in, func(t *testing.T) {
			_, err := loadMaxAgentVersion(in)
			require.ErrorContains(t, err, msg)
			require.ErrorContains(t, err, "_max_agent_version")
		})
	}
}

// ucfg parses an environment-variable value as a YAML scalar, so 9.10 arrives as the float 9.1 even when the
// reference is quoted. It is rejected rather than silently read as "9.1".
func TestMaxAgentVersionEnv(t *testing.T) {
	t.Setenv("FLEET_TEST_MAX_VER", "9.10")
	_, err := loadMaxAgentVersion(`"${FLEET_TEST_MAX_VER}"`)
	require.ErrorContains(t, err, "quoted string")
}

func TestMaxAgentVersionMergeRoundTrip(t *testing.T) {
	base, err := LoadFile(filepath.Join("testdata", "basic.yml"))
	require.NoError(t, err)
	other, err := LoadFile(filepath.Join("testdata", "basic.yml"))
	require.NoError(t, err)
	other.Inputs[0].Server.Features.MaxAgentVersion = "9.10"

	merged, err := base.Merge(other)
	require.NoError(t, err)
	require.Len(t, merged.Inputs, 1)
	require.Equal(t, AgentVersionLimit("9.10"), merged.Inputs[0].Server.Features.MaxAgentVersion)
}

func builtinMajor(t *testing.T) int {
	t.Helper()
	v, err := goversion.NewVersion(fleetversion.DefaultVersion)
	require.NoError(t, err)
	return v.Segments()[0]
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
