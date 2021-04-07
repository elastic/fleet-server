// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limit

import (
	"errors"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"

	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

type Limiter struct {
	rateLimit *rate.Limiter
	maxLimit  *semaphore.Weighted
}

type ReleaseFunc func()

var (
	ErrRateLimit = errors.New("rate limit")
	ErrMaxLimit  = errors.New("max limit")
)

func NewLimiter(cfg *config.Limit) *Limiter {

	if cfg == nil {
		return &Limiter{}
	}

	l := &Limiter{}

	if cfg.Interval != time.Duration(0) {
		l.rateLimit = rate.NewLimiter(rate.Every(cfg.Interval), cfg.Burst)
	}

	if cfg.Max != 0 {
		l.maxLimit = semaphore.NewWeighted(cfg.Max)
	}

	return l
}

func (l *Limiter) Acquire() (ReleaseFunc, error) {
	releaseFunc := noop

	if l.rateLimit != nil && !l.rateLimit.Allow() {
		return nil, ErrRateLimit
	}

	if l.maxLimit != nil {
		if !l.maxLimit.TryAcquire(1) {
			return nil, ErrMaxLimit
		}
		releaseFunc = l.release
	}

	return releaseFunc, nil
}

func (l *Limiter) release() {
	if l.maxLimit != nil {
		l.maxLimit.Release(1)
	}
}

func noop() {
}
