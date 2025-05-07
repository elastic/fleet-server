// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
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
			log := testlog.SetLogger(t)
			changed := configChangedServer(log, cfg, tc.cfg)
			assert.Equal(t, changed, tc.changed)
		})
	}
}

func Test_initTracer(t *testing.T) {
	testcases := []struct {
		name                 string
		apmActiveEnvVariable string
		expectTracer         bool
		cfg                  config.Instrumentation
	}{{
		name:                 "enabled with env variable",
		apmActiveEnvVariable: "true",
		expectTracer:         true,
		cfg:                  config.Instrumentation{},
	}, {
		name:                 "enabled with config",
		apmActiveEnvVariable: "",
		expectTracer:         true,
		cfg: config.Instrumentation{
			Enabled: true,
		},
	}, {
		name:                 "not enabled",
		apmActiveEnvVariable: "",
		expectTracer:         false,
		cfg:                  config.Instrumentation{},
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testlog.SetLogger(t).WithContext(context.Background())
			f := Fleet{}
			t.Setenv("ELASTIC_APM_ACTIVE", tc.apmActiveEnvVariable)
			tarcer, err := f.initTracer(ctx, tc.cfg)
			assert.Nil(t, err)

			if tc.expectTracer {
				assert.NotNil(t, tarcer)
			} else {
				assert.Nil(t, tarcer)
			}

		})
	}
}
