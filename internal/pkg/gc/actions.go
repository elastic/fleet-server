// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package gc

import (
	"context"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/scheduler"
)

type ActionsCleanupConfig struct {
	cleanupIntervalAfterExpired string
}

type ActionsCleanupOpt func(c *ActionsCleanupConfig)

// isIntervalStringValid validated interval string according to the elasticsearch documentation
// https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#date-math
func isIntervalStringValid(interval string) bool {
	if len(interval) < 2 {
		return false
	}
	if strings.HasPrefix(interval, "-") {
		return false
	}

	num := interval[0 : len(interval)-1]
	suffix := interval[len(num):]

	switch suffix {
	case "y", "M", "w", "d", "h", "H", "m", "s":
		if _, err := strconv.Atoi(num); err == nil {
			return true
		}
	}

	return false
}

func WithCleanupIntervalAfterExpired(cleanupIntervalAfterExpired string) ActionsCleanupOpt {
	return func(c *ActionsCleanupConfig) {
		// Use the interval if valid, otherwise keep the default
		if isIntervalStringValid(cleanupIntervalAfterExpired) {
			c.cleanupIntervalAfterExpired = cleanupIntervalAfterExpired
		}
	}
}

func getActionsGCFunc(bulker bulk.Bulk, cleanupIntervalAfterExpired string) scheduler.WorkFunc {
	return func(ctx context.Context) error {
		return cleanupActions(ctx, dl.FleetActions, bulker,
			WithCleanupIntervalAfterExpired(cleanupIntervalAfterExpired))
	}
}

func cleanupActions(ctx context.Context, index string, bulker bulk.Bulk, opts ...ActionsCleanupOpt) error {
	c := ActionsCleanupConfig{
		cleanupIntervalAfterExpired: defaultCleanupIntervalAfterExpired,
	}

	for _, opt := range opts {
		opt(&c)
	}

	log := log.With().Str("ctx", "fleet actions cleanup").Str("interval", "now-"+c.cleanupIntervalAfterExpired).Logger()

	log.Debug().Msg("delete expired actions")

	deleted, err := dl.DeleteExpiredForIndex(ctx, index, bulker, c.cleanupIntervalAfterExpired)
	if err != nil {
		log.Debug().Err(err).Msg("failed to delete actions")
		return err
	}
	log.Debug().Int64("count", deleted).Msg("deleted expired actions")
	return nil
}
