// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package limit

import (
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"
)

var benchSinkReleaseFunc ReleaseFunc

// BenchmarkLimiterAcquireNoLimit measures Acquire when no limits are configured.
func BenchmarkLimiterAcquireNoLimit(b *testing.B) {
	l := &Limiter{releaseFunc: noop}
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
// The releaseFunc is pre-bound at construction (mirroring NewLimiter) — 0 allocs per call.
func BenchmarkLimiterAcquireWithMax(b *testing.B) {
	l := &Limiter{maxLimit: semaphore.NewWeighted(1)}
	l.releaseFunc = l.release // pre-bind once, as NewLimiter does
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

// BenchmarkWriteError measures writeError using pre-computed response bodies.
func BenchmarkWriteError(b *testing.B) {
	w := httptest.NewRecorder()
	log := zerolog.Nop()
	b.ReportAllocs()
	for b.Loop() {
		w.Body.Reset()
		_ = writeError(&log, w, ErrRateLimit)
	}
}
