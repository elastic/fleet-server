// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package gc

import (
	"context"
	"math/rand"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/scheduler"
	"github.com/elastic/fleet-server/v7/internal/pkg/wait"
)

const (
	defaultMaxWaitInCleanupLoop         = 10 * time.Second // the wait in the cleanup loop between iteration is random
	defaultActionsSelectSize            = 1000
	defaultActionsCleanupBeforeInterval = 24 * 30 * time.Hour
)

type ActionsCleanupConfig struct {
	maxWaitInCleanupLoop  time.Duration
	actionsSelectSize     int
	cleanupBeforeInterval time.Duration
}

type ActionsCleanupOpt func(c *ActionsCleanupConfig)

func WithMaxWaitInCleanupLoop(maxWaitInCleanupLoop time.Duration) ActionsCleanupOpt {
	return func(c *ActionsCleanupConfig) {
		c.maxWaitInCleanupLoop = maxWaitInCleanupLoop
	}
}

func WithActionSelectSize(actionsSelectSize int) ActionsCleanupOpt {
	return func(c *ActionsCleanupConfig) {
		c.actionsSelectSize = actionsSelectSize
	}
}

func WithActionCleanupBeforeInterval(cleanupBeforeInterval time.Duration) ActionsCleanupOpt {
	return func(c *ActionsCleanupConfig) {
		c.cleanupBeforeInterval = cleanupBeforeInterval
	}
}

func getActionsGCFunc(bulker bulk.Bulk, cleanupBeforeInterval time.Duration) scheduler.WorkFunc {
	return func(ctx context.Context) error {
		return cleanupActions(ctx, dl.FleetActions, bulker,
			WithActionCleanupBeforeInterval(cleanupBeforeInterval))
	}
}

func cleanupActions(ctx context.Context, index string, bulker bulk.Bulk, opts ...ActionsCleanupOpt) error {
	log := log.With().Str("ctx", "fleet actions cleanup").Logger()

	c := ActionsCleanupConfig{
		cleanupBeforeInterval: defaultActionsCleanupBeforeInterval,
		actionsSelectSize:     defaultActionsSelectSize,
		maxWaitInCleanupLoop:  defaultMaxWaitInCleanupLoop,
	}

	for _, opt := range opts {
		opt(&c)
	}

	// Cleanup expired actions where expired timetamp is older than current time minus cleanupBeforeInterval
	// Example: cleanup up actions that expired more than two weeks ago
	expiredBefore := time.Now().Add(-c.cleanupBeforeInterval)

	// Random generator for calculating random pause duration in the cleanup loop
	r := rand.New(rand.NewSource(time.Now().Unix()))

	var (
		hits []es.HitT
		err  error
	)

	for {
		log.Debug().Str("expired_before", expiredBefore.UTC().Format(time.RFC3339)).Msgf("find actions that expired before given date/time")
		hits, err = dl.FindExpiredActionsHitsForIndex(ctx, index, bulker, expiredBefore, c.actionsSelectSize)
		if err != nil {
			return err
		}

		if len(hits) == 0 {
			log.Debug().Msg("no more expired actions found, done cleaning")
			return nil
		}

		log.Debug().Int("count", len(hits)).Msg("delete expired actions")
		if len(hits) > 0 {
			ops := make([]bulk.MultiOp, len(hits))
			for i := 0; i < len(hits); i++ {
				ops[i] = bulk.MultiOp{Index: index, Id: hits[i].Id}
			}

			res, err := bulker.MDelete(ctx, ops)
			if err != nil {
				// The error is logged
				log.Debug().Err(err).Msg("failed to delete actions")
			}
			for i, r := range res {
				if r.Error != nil {
					err = es.TranslateError(r.Status, r.Error)
					if err != nil {
						log.Debug().Err(err).Str("action_id", hits[i].Id).Msg("failed to delete action")
						if r.Status == http.StatusNotFound {
							err = nil
						}
					}
				}
			}
		}

		// If number of records selected is less than max, can exit the cleanup loop
		if len(hits) < c.actionsSelectSize {
			return nil
		}

		// The full number of hits was returned
		// Can potentially have more records
		// Pause before doing another iteration
		if c.maxWaitInCleanupLoop > 0 {
			pauseDuration := time.Duration(r.Int63n(int64(c.maxWaitInCleanupLoop)))
			log.Debug().Dur("pause_duration", pauseDuration).Msg("more actions could be avaiable, pause before the next cleanup cycle")
			// Wait with context some random short interval to avoid tight loops
			err = wait.WithContext(ctx, pauseDuration)
			if err != nil {
				return err
			}
		}
	}
}
