// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package config

import (
	"fmt"
	"github.com/rs/zerolog"
	"strings"
)

// AgentLogging is the log level set on the Agent.
type AgentLogging struct {
	Level string `config:"level"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *AgentLogging) InitDefaults() {
	c.Level = "info"
}

// Validate ensures that the configuration is valid.
func (c *AgentLogging) Validate() error {
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
	Logging AgentLogging `config:"logging"`
}

// Host is the ID of the host of the Agent running this Fleet Server.
type Host struct {
	ID string `config:"id"`
}

// Fleet is the configuration of Agent running inside of Fleet.
type Fleet struct {
	Agent Agent `config:"agent"`
	Host  Host  `config:"host"`
}

func strToLevel(s string) (zerolog.Level, error) {
	l := zerolog.DebugLevel

	s = strings.ToLower(s)
	switch strings.TrimSpace(s) {
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warning":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	default:
		return l, fmt.Errorf("invalid log level; must be one of: debug, info, warning, error")
	}

	return l, nil
}
