// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"time"
)

type Limit struct {
	Interval time.Duration `config:"interval"`
	Burst    int           `config:"burst"`
	Max      int64         `config:"max"`
}

type ServerLimits struct {
	PolicyThrottle    time.Duration `config:"policy_throttle"`
	MaxHeaderByteSize int           `config:"max_header_byte_size"`
	MaxConnections    int           `config:"max_connections"`

	CheckinLimit  Limit `config:"checkin_limit"`
	ArtifactLimit Limit `config:"artifact_limit"`
	EnrollLimit   Limit `config:"enroll_limit"`
	AckLimit      Limit `config:"ack_limit"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *ServerLimits) InitDefaults() {

	c.MaxHeaderByteSize = 8192 // 8k
	c.MaxConnections = 0       // no limit
	c.PolicyThrottle = time.Millisecond * 5

	c.CheckinLimit = Limit{
		Interval: time.Millisecond,
		Burst:    1000,
	}
	c.ArtifactLimit = Limit{
		Interval: time.Millisecond * 5,
		Burst:    25,
		Max:      50,
	}
	c.EnrollLimit = Limit{
		Interval: time.Millisecond * 10,
		Burst:    100,
		Max:      50,
	}
	c.AckLimit = Limit{
		Interval: time.Millisecond * 10,
		Burst:    100,
		Max:      50,
	}
}
