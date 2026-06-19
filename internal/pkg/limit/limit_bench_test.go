// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package limit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

var benchSinkReleaseFunc ReleaseFunc

// BenchmarkLimiterAcquireNoLimit measures Acquire when no limits are configured.
func BenchmarkLimiterAcquireNoLimit(b *testing.B) {
	l := &Limiter{}
	b.ReportAllocs()
	for b.Loop() {
		rf, err := l.Acquire()
		if err != nil {
			b.Fatal(err)
		}
		benchSinkReleaseFunc = rf
	}
}

// BenchmarkLimiterAcquireWithMax measures Acquire when maxLimit is configured.
// The current implementation binds l.release as a new method value (heap alloc) on every call.
func BenchmarkLimiterAcquireWithMax(b *testing.B) {
	l := &Limiter{
		maxLimit: semaphore.NewWeighted(1),
	}
	b.ReportAllocs()
	for b.Loop() {
		rf, err := l.Acquire()
		if err != nil {
			b.Fatal(err)
		}
		rf() // release so next iteration can acquire
		benchSinkReleaseFunc = rf
	}
}

// limiterPreBound is the proposed Limiter variant that pre-binds the release
// function once at construction, eliminating the per-Acquire closure allocation.
type limiterPreBound struct {
	rateLimit   *rate.Limiter
	maxLimit    *semaphore.Weighted
	releaseFunc ReleaseFunc
}

func newLimiterPreBound(max int64, interval time.Duration, burst int) *limiterPreBound {
	l := &limiterPreBound{releaseFunc: noop}
	if interval != 0 {
		l.rateLimit = rate.NewLimiter(rate.Every(interval), burst)
	}
	if max != 0 {
		l.maxLimit = semaphore.NewWeighted(max)
		l.releaseFunc = l.release // bound once at construction, not per-Acquire
	}
	return l
}

func (l *limiterPreBound) release() {
	if l.maxLimit != nil {
		l.maxLimit.Release(1)
	}
}

func (l *limiterPreBound) acquire() (ReleaseFunc, error) {
	if l.rateLimit != nil && !l.rateLimit.Allow() {
		return nil, ErrRateLimit
	}
	if l.maxLimit != nil && !l.maxLimit.TryAcquire(1) {
		return nil, ErrMaxLimit
	}
	return l.releaseFunc, nil
}

// BenchmarkLimiterAcquirePreBound measures Acquire with the pre-bound release function.
// The releaseFunc field is set once at construction and returned directly on each Acquire call.
func BenchmarkLimiterAcquirePreBound(b *testing.B) {
	l := newLimiterPreBound(1, 0, 0)
	b.ReportAllocs()
	for b.Loop() {
		rf, err := l.acquire()
		if err != nil {
			b.Fatal(err)
		}
		rf() // release so next iteration can acquire
		benchSinkReleaseFunc = rf
	}
}

// Pre-computed static response bodies for the proposed writeError optimization.
var (
	staticErrRateLimitBody = []byte(`{"statusCode":429,"error":"RateLimit","message":"exceeded the rate limit"}`)
	staticErrMaxLimitBody  = []byte(`{"statusCode":429,"error":"MaxLimit","message":"exceeded the max limit"}`)
)

// writeErrorStatic is the proposed writeError implementation using pre-computed response bodies,
// eliminating the json.Marshal call on every 429 response.
func writeErrorStatic(log *zerolog.Logger, w http.ResponseWriter, err error) error {
	var body []byte
	switch {
	case errors.Is(err, ErrRateLimit):
		body = staticErrRateLimitBody
	case errors.Is(err, ErrMaxLimit):
		body = staticErrMaxLimitBody
	default:
		log.Error().Err(err).Msg("Encountered unknown limiter error")
		body = []byte(`{"statusCode":429,"error":"UnknownLimiterError","message":"unknown limiter error encountered"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusTooManyRequests)
	_, wErr := w.Write(body)
	return wErr
}

// BenchmarkWriteError measures the current writeError: json.Marshal of a struct on every call.
func BenchmarkWriteError(b *testing.B) {
	w := httptest.NewRecorder()
	log := zerolog.Nop()
	b.ReportAllocs()
	for b.Loop() {
		w.Body.Reset()
		_ = writeError(&log, w, ErrRateLimit)
	}
}

// BenchmarkWriteErrorStatic measures the proposed writeError using pre-computed response bodies.
func BenchmarkWriteErrorStatic(b *testing.B) {
	w := httptest.NewRecorder()
	log := zerolog.Nop()
	b.ReportAllocs()
	for b.Loop() {
		w.Body.Reset()
		_ = writeErrorStatic(&log, w, ErrRateLimit)
	}
}
