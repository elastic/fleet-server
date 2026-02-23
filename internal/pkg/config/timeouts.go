// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"time"
)

// ServerTimeouts is the configuration for the server timeouts
type ServerTimeouts struct {
	Read             time.Duration `config:"read"`
	Write            time.Duration `config:"write"`
	Idle             time.Duration `config:"idle"`
	ReadHeader       time.Duration `config:"read_header"`
	CheckinTimestamp time.Duration `config:"checkin_timestamp"`
	CheckinLongPoll  time.Duration `config:"checkin_long_poll"`
	CheckinJitter    time.Duration `config:"checkin_jitter"`
	CheckinMaxPoll   time.Duration `config:"checkin_max_poll"`
	Drain            time.Duration `config:"drain"`
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
	// Use a large timeout to accommodate the authentication lag.  Add a ReadHeader timeout
	// below to handle preAuth.
	c.Read = 60 * time.Second

	// Read header timeout covers ACCEPT to the end of the HTTP headers.
	// Note that for TLS, this include the TLS handshake as well.
	// This is considered preauth in this server, so limit the timeout to something reasonable.
	c.ReadHeader = 5 * time.Second

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled.   Because TLS handshakes are expensive
	// for the server, avoid aggressive connection close with generous idle timeout.
	// Set to 35s (slightly above the OTel Collector's default ~30s OpAMP polling interval)
	// to ensure idle connections are not closed just as a new OpAMP request comes in.
	c.Idle = 35 * time.Second

	// The write timeout for HTTPS covers the time from ACCEPT to the end of the response write;
	// so in that case it covers the TLS handshake.  If the connection is reused, the write timeout
	// covers the time from the end of the request header to the end of the response write.
	// Set to a very large timeout to allow for slow backend; must be at least as large as Read timeout plus Long Poll.
	c.Write = 10 * time.Minute

	// Write out a timestamp to elastic on this timeout during long poll
	c.CheckinTimestamp = 30 * time.Second

	// Long poll timeout, will be short-circuited on policy change
	c.CheckinLongPoll = 5 * time.Minute

	// Jitter subtracted from c.CheckinLongPoll. Disabled if zero.
	c.CheckinJitter = 30 * time.Second

	// MaxPoll is the maximum allowed value for a long poll when the client specified poll_timeout value is used.
	// The long poll value is poll_timeout-2m, and the request's write timeout is set to poll_timeout-1m
	// CheckinMaxPoll values of less then 1m are effectively ignored and a 1m limit is used.
	c.CheckinMaxPoll = time.Hour

	// Drain is the max duration that a server will keep connections open when a shutdown signal is received in order to gracefully handle in progress-requests.
	// It is used as a context timeout value for server.ShutDown(ctx).
	// A long-poll checkin connection should immediately return with a 200 status and the same ackToken it was sent, the same as if the long-poll completed with no changes detected.
	c.Drain = 10 * time.Second
}
