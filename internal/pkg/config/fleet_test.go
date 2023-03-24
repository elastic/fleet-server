// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestFleetAgentDefaultLevel(t *testing.T) {
	cfg := Fleet{}

	if cfg.Agent.Logging.LogLevel() != zerolog.DebugLevel {
		t.Errorf("expected DebugLevel got: %s", cfg.Agent.Logging.LogLevel())
	}
}

func TestFleetCopyNoLogging(t *testing.T) {
	c1 := &Fleet{
		Agent: Agent{
			ID:      "test-id",
			Version: "test-ver",
		},
		Host: Host{
			ID:   "test-id",
			Name: "test-host",
		},
	}

	c2 := &Fleet{
		Agent: Agent{
			ID:      "test-id",
			Version: "test-ver",
			Logging: AgentLogging{
				Level: "info",
			},
		},
		Host: Host{
			ID:   "test-id",
			Name: "test-host",
		},
	}

	assert.Equal(t, c1, c2.CopyNoLogging())
}
