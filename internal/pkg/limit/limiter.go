// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package limit provides the ability to rate limit the api server.
package limit

import (
	"net/http"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/julienschmidt/httprouter"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

// Limiter enforces rate limits for each API endpoint.
type Limiter struct {
	checkin  *limiter
	artifact *limiter
	enroll   *limiter
	ack      *limiter
	status   *limiter
	log      zerolog.Logger
}

// Create a new Limiter using the specified limits.
func NewLimiter(addr string, cfg *config.ServerLimits) *Limiter {
	return &Limiter{
		checkin:  newLimiter(&cfg.CheckinLimit),
		artifact: newLimiter(&cfg.ArtifactLimit),
		enroll:   newLimiter(&cfg.EnrollLimit),
		ack:      newLimiter(&cfg.AckLimit),
		status:   newLimiter(&cfg.StatusLimit),
		log:      log.With().Str("addr", addr).Logger(),
	}
}

// WhapCheckin wraps the checkin handler with the rate limiter and tracks statistics for the endpoint.
func (l *Limiter) WrapCheckin(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.checkin.wrap(l.log.With().Str("route", "checkin").Logger(), zerolog.WarnLevel, h, i)
}

// WhapArtifact wraps the artifact handler with the rate limiter and tracks statistics for the endpoint.
func (l *Limiter) WrapArtifact(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.artifact.wrap(l.log.With().Str("route", "artifact").Logger(), zerolog.DebugLevel, h, i)
}

// WhapEnroll wraps the enroll handler with the rate limiter and tracks statistics for the endpoint.
func (l *Limiter) WrapEnroll(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.enroll.wrap(l.log.With().Str("route", "enroll").Logger(), zerolog.DebugLevel, h, i)
}

// WhapAck wraps the ack handler with the rate limiter and tracks statistics for the endpoint.
func (l *Limiter) WrapAck(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.ack.wrap(l.log.With().Str("route", "ack").Logger(), zerolog.DebugLevel, h, i)
}

// WhapStatus wraps the checkin handler with the rate limiter and tracks statistics for the endpoint.
func (l *Limiter) WrapStatus(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.status.wrap(l.log.With().Str("route", "status").Logger(), zerolog.DebugLevel, h, i)
}

// StatIncer is the interface used to count statistics associated with an endpoint.
type StatIncer interface {
	IncError(error)
	IncStart() func()
}

type releaseFunc func()

type limiter struct {
	rateLimit *rate.Limiter
	maxLimit  *semaphore.Weighted
}

func newLimiter(cfg *config.Limit) *limiter {
	if cfg == nil {
		return &limiter{}
	}

	l := &limiter{}

	if cfg.Interval != time.Duration(0) {
		l.rateLimit = rate.NewLimiter(rate.Every(cfg.Interval), cfg.Burst)
	}

	if cfg.Max != 0 {
		l.maxLimit = semaphore.NewWeighted(cfg.Max)
	}

	return l
}

func (l *limiter) acquire() (releaseFunc, error) {
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

func (l *limiter) release() {
	if l.maxLimit != nil {
		l.maxLimit.Release(1)
	}
}

func (l *limiter) wrap(logger zerolog.Logger, level zerolog.Level, h httprouter.Handle, i StatIncer) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		dfunc := i.IncStart()
		defer dfunc()

		lf, err := l.acquire()
		if err != nil {
			logger.WithLevel(level).Err(err).Msg("limit reached")
			if wErr := writeError(w, err); wErr != nil {
				logger.Error().Err(wErr).Msg("fail writing error response")
			}
			i.IncError(err)
			return
		}
		defer lf()
		h(w, r, p)
	}
}

func noop() {
}
