// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import "time"

const (
	defaultScheduleInterval            = time.Hour
	defaultCleanupIntervalAfterExpired = "30d" // cleanup expired actions with expiration time older than 30 days from now
)

// GC is the configuration for the Fleet Server data garbage collection.
// Currently manages the expired actions cleanup
type GC struct {
	ScheduleInterval            time.Duration `config:"schedule_interval"`
	CleanupAfterExpiredInterval string        `config:"cleanup_after_expired_interval"`
}

func (g *GC) InitDefaults() {
	g.ScheduleInterval = defaultScheduleInterval
	g.CleanupAfterExpiredInterval = defaultCleanupIntervalAfterExpired
}
