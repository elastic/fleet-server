// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"strings"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"

	"github.com/stretchr/testify/require"
)

func TestAgentModeFlag(t *testing.T) {
	tests := []struct {
		name   string
		flags  []string
		expect func() *config.Config
	}{{
		name:  "no flags",
		flags: []string{},
		expect: func() *config.Config {
			cfg := &config.Config{}
			cfg.InitDefaults()
			cfg.Output.Elasticsearch.InitDefaults() // NOTE this is implicitly called when ucfg parses the top level cfg object, but we need to explicitly call it for testing.
			return cfg
		},
	}, {
		name:  "debug log flag",
		flags: []string{"E logging.level=debug"}, // flag is the k:v separated by a space, key does not have the "-" prefix
		expect: func() *config.Config {
			cfg := &config.Config{}
			cfg.InitDefaults()
			cfg.Output.Elasticsearch.InitDefaults()
			cfg.Logging.Level = "debug"
			return cfg
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewCommand(build.Info{})
			for _, flag := range tc.flags {
				arr := strings.Split(flag, " ")
				err := cmd.Flags().Set(arr[0], arr[1])
				require.NoError(t, err)
			}

			cfgObj := cmd.Flags().Lookup("E").Value.(*config.Flag) //nolint:errcheck // same as in main
			cfgCLI := cfgObj.Config()
			cfg, err := config.FromConfig(cfgCLI)
			require.NoError(t, err)
			require.Equal(t, tc.expect(), cfg)
		})
	}
}
