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
	"time"
)

// ServerTimeouts is the configuration for the server timeouts
type ServerTimeouts struct {
	Read  time.Duration `config:"read"`
	Write time.Duration `config:"write"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *ServerTimeouts) InitDefaults() {
	c.Read = 5 * time.Second
	c.Write = 60 * 10 * time.Second // 10 minutes (long poll)
}

// ServerProfile is the configuration for profiling the server.
type ServerProfile struct {
	Bind string `config:"bind"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *ServerProfile) InitDefaults() {
	c.Bind = "localhost:6060"
}

// ServerTLS is the TLS configuration for running the TLS endpoint.
type ServerTLS struct {
	Key  string `config:"key"`
	Cert string `config:"cert"`
}

// Server is the configuration for the server
type Server struct {
	Host              string         `config:"host"`
	Port              uint16         `config:"port"`
	TLS               ServerTLS      `config:"tls"`
	Timeouts          ServerTimeouts `config:"timeouts"`
	MaxHeaderByteSize int            `config:"max_header_byte_size"`
	RateLimitBurst    int            `config:"rate_limit_burst"`
	RateLimitInterval time.Duration  `config:"rate_limit_interval"`
	MaxEnrollPending  int64          `config:"max_enroll_pending"`
	Profile           ServerProfile  `config:"profile"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Server) InitDefaults() {
	c.Host = "0.0.0.0"
	c.Port = 8000
	c.Timeouts.InitDefaults()
	c.MaxHeaderByteSize = 8192 // 8k
	c.RateLimitBurst = 1024
	c.RateLimitInterval = 5 * time.Millisecond
	c.MaxEnrollPending = 64
	c.Profile.InitDefaults()
}

// Input is the input defined by Agent to run Fleet Server.
type Input struct {
	Type   string `config:"type"`
	Server Server `config:"server"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Input) InitDefaults() {
	c.Type = "fleet-server"
	c.Server.InitDefaults()
}

// Validate ensures that the configuration is valid.
func (c *Input) Validate() error {
	if c.Type != "fleet-server" {
		return fmt.Errorf("input type must be fleet-server")
	}
	return nil
}
