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
const kDefaultInternalHost = "localhost"
const kDefaultInternalPort = 8221

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
	InternalPort      uint16                  `config:"internal_port"`
	TLS               *tlscommon.ServerConfig `config:"ssl"`
	Timeouts          ServerTimeouts          `config:"timeouts"`
	Profiler          ServerProfiler          `config:"profiler"`
	CompressionLevel  int                     `config:"compression_level"`
	CompressionThresh int                     `config:"compression_threshold"`
	Limits            ServerLimits            `config:"limits"`
	Runtime           Runtime                 `config:"runtime"`
	Bulk              ServerBulk              `config:"bulk"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Server) InitDefaults() {
	c.Host = kDefaultHost
	c.Port = kDefaultPort
	c.InternalPort = kDefaultInternalPort
	c.Timeouts.InitDefaults()
	c.CompressionLevel = flate.BestSpeed
	c.CompressionThresh = 1024
	c.Profiler.InitDefaults()
	c.Limits.InitDefaults()
	c.Runtime.InitDefaults()
	c.Bulk.InitDefaults()
}

// BindEndpoints returns the binding address for the all HTTP server listeners.
func (c *Server) BindEndpoints() []string {
	primaryAddress := c.BindAddress()
	endpoints := make([]string, 0, 2)
	endpoints = append(endpoints, primaryAddress)

	if internalAddress := c.BindInternalAddress(); internalAddress != "" && internalAddress != ":0" && internalAddress != primaryAddress {
		endpoints = append(endpoints, internalAddress)
	}

	return endpoints
}

// BindAddress returns the binding address for the HTTP server.
func (c *Server) BindAddress() string {
	return bindAddress(c.Host, c.Port)
}

// BindInternalAddress returns the binding address for the internal HTTP server.
func (c *Server) BindInternalAddress() string {
	if c.InternalPort <= 0 {
		return bindAddress(kDefaultInternalHost, kDefaultInternalPort)
	}

	return bindAddress(kDefaultInternalHost, c.InternalPort)
}

func bindAddress(host string, port uint16) string {
	if strings.Count(host, ":") > 1 && strings.Count(host, "]") == 0 {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, port)
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
