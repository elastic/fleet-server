// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/stretchr/testify/assert"
)

func Test_configChangedServer(t *testing.T) {
	testcases := []struct {
		name    string
		cfg     *config.Config
		changed bool
	}{{
		name: "no changes",
		cfg: &config.Config{
			Fleet: config.Fleet{
				Agent: config.Agent{
					ID:      "test-id",
					Version: "test-version",
					Logging: config.AgentLogging{
						Level: "info",
					},
				},
			},
			Logging: config.Logging{
				Level: "info",
			},
			Inputs: []config.Input{config.Input{}},
		},
		changed: false,
	}, {
		name: "logging changes",
		cfg: &config.Config{
			Fleet: config.Fleet{
				Agent: config.Agent{
					ID:      "test-id",
					Version: "test-version",
					Logging: config.AgentLogging{
						Level: "info",
					},
				},
			},
			Logging: config.Logging{
				Level: "debug",
			},
			Inputs: []config.Input{config.Input{}},
		},
		changed: false,
	}, {
		name: "fleet agent logging chagnes",
		cfg: &config.Config{
			Fleet: config.Fleet{
				Agent: config.Agent{
					ID:      "test-id",
					Version: "test-version",
					Logging: config.AgentLogging{
						Level: "debug",
					},
				},
			},
			Logging: config.Logging{
				Level: "info",
			},
			Inputs: []config.Input{config.Input{}},
		},
		changed: false,
	}, {
		name: "fleet agent change",
		cfg: &config.Config{
			Fleet: config.Fleet{
				Agent: config.Agent{
					ID:      "test-id",
					Version: "test-new-version",
					Logging: config.AgentLogging{
						Level: "info",
					},
				},
			},
			Logging: config.Logging{
				Level: "info",
			},
			Inputs: []config.Input{config.Input{}},
		},
		changed: true,
	}}

	cfg := &config.Config{
		Fleet: config.Fleet{
			Agent: config.Agent{
				ID:      "test-id",
				Version: "test-version",
				Logging: config.AgentLogging{
					Level: "info",
				},
			},
		},
		Logging: config.Logging{
			Level: "info",
		},
		Inputs: []config.Input{config.Input{}},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			changed := configChangedServer(cfg, tc.cfg)
			assert.Equal(t, changed, tc.changed)
		})
	}
}
