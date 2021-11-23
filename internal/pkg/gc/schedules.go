// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package gc

import (
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/scheduler"
)

const (
	defaultScheduleInterval            = time.Hour
	defaultCleanupIntervalAfterExpired = "30d" // cleanup with expiration older than 30 days from now
)

// Schedules returns the GC schedules
func Schedules(bulker bulk.Bulk, scheduleInterval time.Duration, cleanupIntervalAfterExpired string) []scheduler.Schedule {
	if scheduleInterval == 0 {
		scheduleInterval = defaultScheduleInterval
	}
	if cleanupIntervalAfterExpired == "" {
		cleanupIntervalAfterExpired = defaultCleanupIntervalAfterExpired
	}

	return []scheduler.Schedule{
		{
			Name:     "fleet actions cleanup",
			Interval: scheduleInterval,
			WorkFn:   getActionsGCFunc(bulker, cleanupIntervalAfterExpired),
		},
	}
}
