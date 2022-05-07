// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package scheduler provides the ability to run functions on a schedule
package scheduler

import (
	"context"
	"errors"
	"time"

	"math/rand"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

const (
	defaultSplayPercent  = 10
	defaultFirstRunDelay = 10 * time.Second
)

// WorkFunc is the type of function a Scheduler can run
type WorkFunc func(ctx context.Context) error

// Schedule tracks when to execute a WorkFunc
type Schedule struct {
	Name     string
	Interval time.Duration // Time between executions
	WorkFn   WorkFunc
}

// Scheduler tracks scheduled functions.
type Scheduler struct {
	log zerolog.Logger

	splayPercent  int
	firstRunDelay time.Duration // Interval to run the scheduled function for the first time since the scheduler started, splayed as well.

	rand      *rand.Rand
	schedules []Schedule
}

// OptFunc is a functional option used to configure a scheduler
type OptFunc func(*Scheduler) error

// WithSplayPercent sets the splay value as a percentage.
// Only values less then 100 are allowed.
func WithSplayPercent(splayPercent uint) OptFunc {
	return func(s *Scheduler) error {
		if splayPercent >= 100 {
			return errors.New("invalid splay value, expected < 100")
		}
		s.splayPercent = int(splayPercent)
		return nil
	}
}

// WithFirstRunDelay sets the amount of time that scheduled functions will wait on the first execution.
func WithFirstRunDelay(delay time.Duration) OptFunc {
	return func(s *Scheduler) error {
		s.firstRunDelay = delay
		return nil
	}
}

// New creates a new Scheduler with the specified schedules.
// Schedules may not be added to a scheduler after creation.
func New(schedules []Schedule, opts ...OptFunc) (*Scheduler, error) {
	s := &Scheduler{
		log:           log.With().Str("ctx", "elasticsearch CG scheduler").Logger(),
		splayPercent:  defaultSplayPercent,
		firstRunDelay: defaultFirstRunDelay,
		rand:          rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec // used for timing offsets
		schedules:     schedules,
	}

	for _, opt := range opts {
		err := opt(s)
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Run executes all scheduled function according to their schedules.
// Schedule Interval times are garunteed minium values (if a execution takes a very long time, the scheduler will wait Interval before running the function again).
// It is a blocking operation.
func (s *Scheduler) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	for _, schedule := range s.schedules {
		g.Go(s.getRunScheduleFunc(ctx, schedule))
	}
	return g.Wait()
}

func (s *Scheduler) getRunScheduleFunc(ctx context.Context, schedule Schedule) func() error {
	return func() error {
		log := log.With().Str("schedule", schedule.Name).Logger()

		t := time.NewTimer(s.intervalWithSplay(s.firstRunDelay)) // Initial schedule to run right away with splayed randomly delay
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Debug().Msg("exiting on context cancel")
				return nil
			case <-t.C:
				runSchedule(ctx, log, schedule)
				t.Reset(s.intervalWithSplay(schedule.Interval))
			}
		}
	}
}

func (s *Scheduler) intervalWithSplay(interval time.Duration) time.Duration {
	percent := 100 - s.splayPercent + s.rand.Intn(2*s.splayPercent+1)
	return time.Duration(int64(interval) / int64(100.0) * int64(percent))
}

func runSchedule(ctx context.Context, log zerolog.Logger, schedule Schedule) {
	log.Debug().Dur("interval", schedule.Interval).Msg("started")

	err := schedule.WorkFn(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed running schedule function")
	}

	log.Debug().Msg("finished")
}
