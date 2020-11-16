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

// ServerTimeouts is the configuration for the server timeouts
type ServerTimeouts struct {
	Read  int `config:"read"`
	Write int `config:"write"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *ServerTimeouts) InitDefaults() {
	c.Read = 5        // 5 seconds
	c.Write = 60 * 10 // 10 minutes (long poll)
}

// Server is the configuration for the server
type Server struct {
	Host     string         `config:"host"`
	Port     uint16         `config:"host"`
	Timeouts ServerTimeouts `config:"timeouts"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Server) InitDefaults() {
	c.Host = "0.0.0.0"
	c.Port = 8000
}
