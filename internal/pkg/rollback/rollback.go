// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package rollback provides callback function registration that can be used to trigger a rollback.
package rollback

import (
	"context"

	"github.com/rs/zerolog"
)

// RollbackFunc is a function that is called in order to perform a rollback.
type RollbackFunc func(ctx context.Context) error

type rollbackInfo struct {
	name string
	fn   RollbackFunc
}

// Rollback is used to track RollbackFuncs
type Rollback struct {
	log zerolog.Logger
	rbi []rollbackInfo
}

// New returns a new Rollback.
func New(log zerolog.Logger) *Rollback {
	return &Rollback{
		log: log,
	}
}

// Register adds the named function to Rollback
func (r *Rollback) Register(name string, fn RollbackFunc) {
	r.rbi = append(r.rbi, rollbackInfo{name, fn})
}

// Rollback execute all rollback functions, log errors, and return the first error afterwards.
func (r *Rollback) Rollback(ctx context.Context) (err error) {
	for _, rb := range r.rbi {
		log := r.log.With().Str("name", rb.name).Logger()
		log.Debug().Msg("rollback function called")
		if rerr := rb.fn(ctx); rerr != nil {
			log.Error().Err(rerr).Msg("rollback function failed")
			if err == nil {
				err = rerr
			}
		} else {
			log.Debug().Msg("rollback function succeeded")
		}
	}
	return //nolint:nakedret // short function
}
