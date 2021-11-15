// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"compress/flate"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/beats/v7/libbeat/common/transport/tlscommon"
)

const kDefaultHost = "0.0.0.0"
const kDefaultPort = 8220

// Policy is the configuration policy to use.
type Policy struct {
	ID string `config:"id"`
}

// ServerProfiler is the configuration for profiling the server.
type ServerProfiler struct {
	Enabled bool   `config:"enabled"`
	Bind    string `config:"bind"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *ServerProfiler) InitDefaults() {
	c.Enabled = false
	c.Bind = "localhost:6060"
}

// ServerTLS is the TLS configuration for running the TLS endpoint.
type ServerTLS struct {
	Key  string `config:"key"`
	Cert string `config:"cert"`
}

type ServerBulk struct {
	FlushInterval       time.Duration `config:"flush_interval"`
	FlushThresholdCount int           `config:"flush_threshold_cnt"`
	FlushThresholdSize  int           `config:"flush_threshold_size"`
	FlushMaxPending     int           `config:"flush_max_pending"`
}

func (c *ServerBulk) InitDefaults() {
	c.FlushInterval = 250 * time.Millisecond
	c.FlushThresholdCount = 2048
	c.FlushThresholdSize = 1024 * 1024
	c.FlushMaxPending = 8
}

// Server is the configuration for the server
type Server struct {
	Host              string                  `config:"host"`
	Port              uint16                  `config:"port"`
	TLS               *tlscommon.ServerConfig `config:"ssl"`
	Timeouts          ServerTimeouts          `config:"timeouts"`
	Profiler          ServerProfiler          `config:"profiler"`
	CompressionLevel  int                     `config:"compression_level"`
	CompressionThresh int                     `config:"compression_threshold"`
	Limits            ServerLimits            `config:"limits"`
	Runtime           Runtime                 `config:"runtime"`
	Bulk              ServerBulk              `config:"bulk"`
	GC                GC                      `config:"gc"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Server) InitDefaults() {
	c.Host = kDefaultHost
	c.Port = kDefaultPort
	c.Timeouts.InitDefaults()
	c.CompressionLevel = flate.BestSpeed
	c.CompressionThresh = 1024
	c.Profiler.InitDefaults()
	c.Limits.InitDefaults()
	c.Runtime.InitDefaults()
	c.Bulk.InitDefaults()
	c.GC.InitDefaults()
}

// BindAddress returns the binding address for the HTTP server.
func (c *Server) BindAddress() string {
	host := c.Host
	if strings.Count(host, ":") > 1 && strings.Count(host, "]") == 0 {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, c.Port)
}

// Input is the input defined by Agent to run Fleet Server.
type Input struct {
	Type    string  `config:"type"`
	Policy  Policy  `config:"policy"`
	Server  Server  `config:"server"`
	Cache   Cache   `config:"cache"`
	Monitor Monitor `config:"monitor"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Input) InitDefaults() {
	c.Type = "fleet-server"
	c.Server.InitDefaults()
	c.Cache.InitDefaults()
	c.Monitor.InitDefaults()
}

// Validate ensures that the configuration is valid.
func (c *Input) Validate() error {
	if c.Type != "fleet-server" {
		return fmt.Errorf("input type must be fleet-server")
	}
	return nil
}
