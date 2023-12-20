// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package limit provides the ability to rate limit the api server.
package limit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

type releaseFunc func()

// StatIncer is the interface used to count statistics associated with an endpoint.
type StatIncer interface {
	IncError(error, ...attribute.KeyValue)
	IncStart(...attribute.KeyValue) func()
}

type Limiter struct {
	rateLimit *rate.Limiter
	maxLimit  *semaphore.Weighted
}

func NewLimiter(cfg *config.Limit) *Limiter {
	l := &Limiter{}

	if cfg == nil {
		return l
	}

	if cfg.Interval != time.Duration(0) {
		l.rateLimit = rate.NewLimiter(rate.Every(cfg.Interval), cfg.Burst)
	}

	if cfg.Max != 0 {
		l.maxLimit = semaphore.NewWeighted(cfg.Max)
	}

	return l
}

func (l *Limiter) acquire() (releaseFunc, error) {
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

func (l *Limiter) Wrap(name string, si StatIncer, ll zerolog.Level) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// attrs is a copy of api.serverAttrs // TODO maybe pass it as a function?
			p, _ := strconv.Atoi(r.URL.Port())
			attrs := []attribute.KeyValue{
				semconv.ServerAddress(r.URL.Hostname()),
				semconv.ServerPort(p),
			}
			if si != nil {
				dfunc := si.IncStart(attrs...)
				defer dfunc()
			}

			lf, err := l.acquire()
			if err != nil {
				hlog.FromRequest(r).WithLevel(ll).Str("route", name).Err(err).Msg("limit reached")
				if wErr := writeError(hlog.FromRequest(r), w, err); wErr != nil {
					hlog.FromRequest(r).Error().Err(wErr).Msg("fail writing error response")
				}
				if si != nil {
					si.IncError(err, attrs...)
				}
				return
			}
			defer lf()
			next.ServeHTTP(w, r)
		})
	}
}

func noop() {
}
