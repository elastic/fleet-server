// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"compress/flate"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

const (
	kDefaultHost         = "0.0.0.0"
	kDefaultPort         = 8220
	kDefaultInternalHost = "localhost"
	kDefaultInternalPort = 8221
	fleetInputType       = "fleet-server"
)

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
type (
	Server struct {
		Host               string                  `config:"host"`
		Port               uint16                  `config:"port"`
		InternalPort       uint16                  `config:"internal_port"`
		TLS                *tlscommon.ServerConfig `config:"ssl"`
		Timeouts           ServerTimeouts          `config:"timeouts"`
		Profiler           ServerProfiler          `config:"profiler"`
		CompressionLevel   int                     `config:"compression_level"`
		CompressionThresh  int                     `config:"compression_threshold"`
		Limits             ServerLimits            `config:"limits"`
		Runtime            Runtime                 `config:"runtime"`
		Bulk               ServerBulk              `config:"bulk"`
		GC                 GC                      `config:"gc"`
		Instrumentation    Instrumentation         `config:"instrumentation"`
		StaticPolicyTokens StaticPolicyTokens      `config:"static_policy_tokens"`
		PGP                PGP                     `config:"pgp"`
		PDKDF2             PBKDF2                  `config:"pdkdf2"`
		Features           FeatureFlags            `config:"feature_flags"`
	}

	StaticPolicyTokens struct {
		// Enabled is a flag to enable static policy tokens
		Enabled bool `config:"enabled"`
		// PolicyTokens is a list of policy tokens
		PolicyTokens []PolicyToken `config:"policy_tokens"`
	}

	// PolicyToken is a static token for single policy
	PolicyToken struct {
		TokenKey string `config:"token_key"`
		PolicyID string `config:"policy_id"`
	}

	// FeatureFlags contains toggles to enable new behaviour, or restore old behaviour.
	FeatureFlags struct {
		// IgnoreCheckinPolicyID when true will ignore the agent_policy_id and policy_revision_idx attributes in checkin request bodies.
		// This setting restores previous behaviour where all POLICY_CHANGE actions need an explicit ack.
		IgnoreCheckinPolicyID bool `config:"ignore_checkin_policy_id"`

		// EnableOpAMP when true will enable the OpAMP endpoint.
		EnableOpAMP bool `config:"enable_opamp"`
	}
)

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
	c.GC.InitDefaults()
	c.PGP.InitDefaults()
	c.PDKDF2.InitDefaults()
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
	c.Type = fleetInputType
	c.Server.InitDefaults()
	c.Cache.InitDefaults()
	c.Monitor.InitDefaults()
}

// Validate ensures that the configuration is valid.
func (c *Input) Validate() error {
	if c.Type != fleetInputType {
		return fmt.Errorf("input type must be %q", fleetInputType)
	}
	return nil
}
