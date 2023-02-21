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
	MaxBody  int64         `config:"max_body_byte_size"`
}

type ServerLimits struct {
	MaxAgents         int           `config:"max_agents"`
	PolicyThrottle    time.Duration `config:"policy_throttle"`
	MaxHeaderByteSize int           `config:"max_header_byte_size"`
	MaxConnections    int           `config:"max_connections"`

	CheckinLimit     Limit `config:"checkin_limit"`
	ArtifactLimit    Limit `config:"artifact_limit"`
	EnrollLimit      Limit `config:"enroll_limit"`
	AckLimit         Limit `config:"ack_limit"`
	StatusLimit      Limit `config:"status_limit"`
	UploadFileLimit  Limit `config:"upload_file_limit"`
	UploadChunkLimit Limit `config:"upload_chunk_limit"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *ServerLimits) InitDefaults() {
	c.LoadLimits(loadLimits(0))
}

func (c *ServerLimits) LoadLimits(limits *envLimits) {
	l := limits.Server

	if c.MaxHeaderByteSize == 0 {
		c.MaxHeaderByteSize = 8192 // 8k
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = l.MaxConnections
	}
	if c.PolicyThrottle == 0 {
		c.PolicyThrottle = l.PolicyThrottle
	}

	c.CheckinLimit = mergeEnvLimit(c.CheckinLimit, l.CheckinLimit)
	c.ArtifactLimit = mergeEnvLimit(c.ArtifactLimit, l.ArtifactLimit)
	c.EnrollLimit = mergeEnvLimit(c.EnrollLimit, l.EnrollLimit)
	c.AckLimit = mergeEnvLimit(c.AckLimit, l.AckLimit)
	c.StatusLimit = mergeEnvLimit(c.StatusLimit, l.StatusLimit)
	c.UploadFileLimit = mergeEnvLimit(c.UploadFileLimit, l.UploadFileLimit)
	c.UploadChunkLimit = mergeEnvLimit(c.UploadChunkLimit, l.UploadChunkLimit)
}

func mergeEnvLimit(L Limit, l limit) Limit {
	result := Limit{
		Interval: L.Interval,
		Burst:    L.Burst,
		Max:      L.Max,
		MaxBody:  L.MaxBody,
	}
	if result.Interval == 0 {
		result.Interval = l.Interval
	}
	if result.Burst == 0 {
		result.Burst = l.Burst
	}
	if result.Max == 0 {
		result.Max = l.Max
	}
	if result.MaxBody == 0 {
		result.MaxBody = l.MaxBody
	}
	return result
}
