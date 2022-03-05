// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/wait"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/sync/errgroup"
)

var (
	errTest = errors.New("errgroup exit")
)

type scheduleTester struct {
	called int
}

func (s *scheduleTester) Run(ctx context.Context) error {
	s.called++
	return nil
}

func TestScheduler(t *testing.T) {

	const (
		scheduleInterval       = 200 * time.Millisecond
		scheduleCancelInterval = 500 * time.Millisecond
		expectedNumberOfCalls  = int(scheduleCancelInterval/scheduleInterval) + 1 // Expected number of calls, plus initial one
	)

	st := scheduleTester{}

	schedules := []Schedule{
		{
			Name:     "test schedule",
			Interval: scheduleInterval,
			WorkFn:   st.Run,
		},
	}

	sched, err := New(schedules, WithFirstRunDelay(0))
	if err != nil {
		t.Fatal(err)
	}

	g, ctx := errgroup.WithContext(context.Background())

	// Run scheduler
	g.Go(func() error {
		return sched.Run(ctx)
	})

	g.Go(func() error {
		wait.WithContext(ctx, 500*time.Millisecond) // nolint:errcheck // Err can be ignore in the test helper.
		// return some error here to cause exit error group wait
		return errTest
	})

	// Wait for result
	err = g.Wait()
	if !errors.Is(err, errTest) {
		t.Errorf("unxpected err, want: %v, got: %v", errTest, err)
	}

	// Expected
	diff := cmp.Diff(expectedNumberOfCalls, st.called)
	if diff != "" {
		t.Fatal(diff)
	}

}
