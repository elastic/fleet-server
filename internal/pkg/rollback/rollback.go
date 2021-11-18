// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package rollback

import (
	"context"

	"github.com/rs/zerolog"
)

type RollbackFunc func(ctx context.Context) error

type rollbackInfo struct {
	name string
	fn   RollbackFunc
}

type Rollback struct {
	log zerolog.Logger
	rbi []rollbackInfo
}

func New(log zerolog.Logger) *Rollback {
	return &Rollback{
		log: log,
	}
}

func (r *Rollback) Register(name string, fn RollbackFunc) {
	r.rbi = append(r.rbi, rollbackInfo{name, fn})
}

func (r *Rollback) Rollback(ctx context.Context) (err error) {
	// Execute all rollback functions, log errors, return the first error
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
	return
}
