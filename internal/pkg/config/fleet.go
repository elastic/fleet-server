// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

// AgentLogging is the log level set on the Agent.
type AgentLogging struct {
	Level string `config:"level"`
}

// Validate ensures that the configuration is valid.
func (c *AgentLogging) Validate() error {
	if c.Level == "" {
		// allowed to be empty because `agent.logging.level` is only
		// an override of the logging level from `logging.level`
		return nil
	}
	if _, err := strToLevel(c.Level); err != nil {
		return err
	}
	return nil
}

// LogLevel returns configured zerolog.Level
func (c *AgentLogging) LogLevel() zerolog.Level {
	l, _ := strToLevel(c.Level)
	return l
}

// Agent is the ID and logging configuration of the Agent running this Fleet Server.
type Agent struct {
	ID      string       `config:"id"`
	Version string       `config:"version"`
	Logging AgentLogging `config:"logging"`
}

// Host is the ID of the host of the Agent running this Fleet Server.
type Host struct {
	ID   string `config:"id"`
	Name string `config:"name"`
}

// Fleet is the configuration of Agent running inside of Fleet.
type Fleet struct {
	DefaultPolicyID string `config:"default_policy_id"`
	Agent           Agent  `config:"agent"`
	Host            Host   `config:"host"`
}

func strToLevel(s string) (zerolog.Level, error) {
	l := zerolog.DebugLevel

	s = strings.ToLower(s)
	switch strings.TrimSpace(s) {
	case "trace":
		l = zerolog.TraceLevel
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warning":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	default:
		return l, fmt.Errorf("invalid log level; must be one of: trace, debug, info, warning, error")
	}

	return l, nil
}
