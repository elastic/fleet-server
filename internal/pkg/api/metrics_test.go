// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package api

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testRegistrySeq disambiguates the throwaway metrics registry name used by
// TestRunCheckinRejectionRateSampler across repeated runs in the same process.
var testRegistrySeq atomic.Int64

func TestComputeRate(t *testing.T) {
	tests := []struct {
		name string
		prev uint64
		cur  uint64
		dt   time.Duration
		want uint64
	}{
		{
			name: "normal delta over one second",
			prev: 100,
			cur:  150,
			dt:   time.Second,
			want: 50,
		},
		{
			name: "normal delta over multiple seconds, rounds to nearest",
			prev: 100,
			cur:  125,
			dt:   10 * time.Second,
			want: 3, // 2.5 rounds to 3
		},
		{
			name: "no delta",
			prev: 100,
			cur:  100,
			dt:   time.Second,
			want: 0,
		},
		{
			name: "zero elapsed time",
			prev: 100,
			cur:  200,
			dt:   0,
			want: 0,
		},
		{
			name: "negative elapsed time",
			prev: 100,
			cur:  200,
			dt:   -time.Second,
			want: 0,
		},
		{
			name: "counter reset (process restart)",
			prev: 1000,
			cur:  5,
			dt:   time.Second,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, computeRate(tt.prev, tt.cur, tt.dt))
		})
	}
}

func TestRunCheckinRejectionRateSampler(t *testing.T) {
	// cntCheckin is a package-level global shared with the checkin route handler
	// and other tests in this package. Swap in a throwaway routeStats registered
	// under a private namespace for the duration of this test, then restore the
	// original so other tests/handlers keep using the real, shared metrics.
	orig := cntCheckin
	t.Cleanup(func() { cntCheckin = orig })

	// newGauge/newCounter register into the package-global prometheus registry,
	// which panics on a duplicate name. Suffix with a per-call counter so this
	// test can safely run more than once in the same process (e.g. `go test
	// -count=N`, or a test-retry mechanism).
	cntCheckin = routeStats{}
	cntCheckin.Register(registry.newRegistry(fmt.Sprintf("test_checkin_rejection_rate_sampler_%d", testRegistrySeq.Add(1))))

	ctx, cancel := context.WithCancel(t.Context())

	const interval = 10 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		done <- RunCheckinRejectionRateSampler(ctx, interval)
	}()

	// The rate gauge is a point-in-time reading: it goes back to 0 on any sample
	// tick with no new rejections since the previous one, by design (it reflects
	// current saturation, not a lifetime total). So rather than injecting a single
	// burst and checking the gauge at an arbitrary later time -- which races
	// against it decaying back to 0 on the next empty tick -- keep simulating
	// rejections for the duration of the test and poll for the gauge having been
	// positive at least once.
	injectorDone := make(chan struct{})
	go func() {
		defer close(injectorDone)
		t := time.NewTicker(interval / 2)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cntCheckin.maxLimit.Add(1)
			}
		}
	}()

	// Stop both goroutines and wait for them to actually exit before this test
	// returns -- registered as Cleanup, like the cntCheckin restoration above, so
	// it still runs if require.Eventually below fails (which unwinds via
	// runtime.Goexit, skipping any code after it). Cleanup funcs run in LIFO
	// order, so this (registered second) runs before the cntCheckin restoration
	// (registered first) -- otherwise that restoration could race with either
	// goroutine still running and mutating the shared cntCheckin global.
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
		<-injectorDone
	})

	require.Eventually(t, func() bool {
		return cntCheckin.maxLimitRate.metric.Get() > 0
	}, 20*interval, interval/4, "expected the rejection rate gauge to become positive while rejections were ongoing")
}
