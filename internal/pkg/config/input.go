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

// ServerTimeouts is the configuration for the server timeouts
type ServerTimeouts struct {
	Read             time.Duration `config:"read"`
	Write            time.Duration `config:"write"`
	Idle             time.Duration `config:"idle"`
	ReadHeader       time.Duration `config:"read_header"`
	CheckinTimestamp time.Duration `config:"checkin_timestamp"`
	CheckinLongPoll  time.Duration `config:"checkin_long_poll"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *ServerTimeouts) InitDefaults() {
	// see https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/

	// The read timeout starts on ACCEPT of the connection, and includes
	// the time to read the entire body (if the body is read, otherwise to the end of the headers).
	// Note that for TLS, this include the TLS handshake as well.
	// In most cases, we are authenticating the apikey and doing an agent record lookup
	// *before* reading the body.  This is purposeful to avoid streaming data from an unauthenticated
	// connection. However, the downside is that if the roundtrip to Elastic is slow, we may
	// end up hitting the Read timeout before actually reading any data off the socket.
	// Use a large timeout to accomodate the authentication lag.  Add a ReadHeader timeout
	// below to handle preAuth.
	c.Read = 60 * time.Second

	// Read header timeout covers ACCEPT to the end of the HTTP headers.
	// Note that for TLS, this include the TLS handshake as well.
	// This is considered preauth in this server, so limit the timeout to something reasonable.
	c.ReadHeader = 5 * time.Second

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled.   Because TLS handshakes are expensive
	// for the server, avoid aggressive connection close with generous idle timeout.
	c.Idle = 30 * time.Second

	// The write timeout for HTTPS covers the time from ACCEPT to the end of the response write;
	// so in that case it covers the TLS handshake.  If the connection is reused, the write timeout
	// covers the time from the end of the request header to the end of the response write.
	// Set to a very large timeout to allow for slow backend; must be at least as large as Read timeout plus Long Poll.
	c.Write = 10 * time.Minute

	c.CheckinTimestamp = 30 * time.Second
	c.CheckinLongPoll = 5 * time.Minute
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

// Server is the configuration for the server
type Server struct {
	Host              string            `config:"host"`
	Port              uint16            `config:"port"`
	TLS               *tlscommon.Config `config:"ssl"`
	Timeouts          ServerTimeouts    `config:"timeouts"`
	Profiler          ServerProfiler    `config:"profiler"`
	CompressionLevel  int               `config:"compression_level"`
	CompressionThresh int               `config:"compression_threshold"`
	Limits            ServerLimits      `config:"limits"`
	Runtime           Runtime           `config:"runtime"`
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
