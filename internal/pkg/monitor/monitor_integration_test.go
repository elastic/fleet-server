// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package monitor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/gcheckpt"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func TestSimpleMonitorEmptyIndex(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetActions)

	runSimpleMonitorTest(t, ctx, index, bulker)
}

func TestSimpleMonitorNonEmptyIndex(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker, _ := ftesting.SetupActions(ctx, t, 1, 12)

	runSimpleMonitorTest(t, ctx, index, bulker)
}

func TestSimpleMonitorWithDebounce(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := ftesting.SetupCleanIndex(ctx, t, ".fleet-actions")

	ch := make(chan model.Action)
	readyCh := make(chan error)
	mon, err := NewSimple(index, bulker.Client(), bulker.Client(),
		WithReadyChan(readyCh),
		WithDebounceTime(time.Second),
	)
	require.NoError(t, err)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		// ready function will add two actions, one immediately, and one after 100ms
		return runSimpleMonitor(t, ctx, mon, readyCh, ch, func(ctx context.Context) error {
			_, err := ftesting.StoreRandomAction(ctx, bulker, index)
			if err != nil {
				return err
			}
			go func(ctx context.Context) {
				time.Sleep(100 * time.Millisecond)
				err := sleep.WithContext(ctx, 100*time.Millisecond)
				if err != nil {
					return
				}
				ftesting.StoreRandomAction(ctx, bulker, index) //nolint:errcheck // test case
			}(ctx)
			return nil
		})
	})

	// read 2 actions and check that time time between both is at least 1s
	g.Go(func() error {
		var ts time.Time
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ch:
				if ts.IsZero() {
					ts = time.Now()
					continue
				}
				dur := time.Since(ts)
				assert.GreaterOrEqual(t, dur, time.Second)
				cn()
			}
		}
	})

	err = g.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSimpleMonitorCheckpointOutOfSync(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker, _ := ftesting.SetupActions(ctx, t, 1, 12)

	g, ctx := errgroup.WithContext(ctx)

	var createdActions []model.Action
	ch := make(chan model.Action)
	readyCh := make(chan error)
	mon, err := NewSimple(index, bulker.Client(), bulker.Client(),
		WithReadyChan(readyCh),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	g.Go(func() error {
		return runSimpleMonitor(t, ctx, mon, readyCh, ch, func(ctx context.Context) error {
			defer wg.Done()
			var err error
			createdActions, err = ftesting.StoreRandomActions(ctx, bulker, index, 1, 7)
			return err
		})
	})

	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ch:
			}
		}
	})

	// Wait until actions are created
	wg.Wait()

	var checkpoint, monCheckpoint sqn.SeqNo
	checkpoint, err = gcheckpt.Query(ctx, bulker.Client(), index)
	require.NoError(t, err)

	t.Logf("Checkpoint before test action delete checkpoint=%d", checkpoint.Value())
	// Delete an action to emulate the gap between the fleet server tracking checkpoint and the index checkpoint
	// The delete causes the checkpoint increment and the fleet-server was not updating it's checkpoint tracked value correctly
	// in these cases.
	idx := len(createdActions) - 1
	err = bulker.Delete(ctx, index, createdActions[idx].Id, bulk.WithRefresh())
	require.NoError(t, err)

	checkpoint, err = gcheckpt.Query(ctx, bulker.Client(), index)
	require.NoError(t, err)
	t.Logf("Checkpoint after test action delete checkpoint=%d", checkpoint.Value())

	// Wait for fleet server monitor checkpoint to be incremented after delete
	m, _ := mon.(*simpleMonitorT)
	timeout := 10 * time.Second // This should not take that long, can wait until the test times out or shorter like this
	start := time.Now()
	for {
		monCheckpoint = m.loadCheckpoint()
		t.Logf("Monitor checkpoint wait_checkpoint=%d got_checkpoint=%d", checkpoint.Value(), monCheckpoint.Value())
		if checkpoint.Value() == monCheckpoint.Value() {
			break
		}

		if time.Since(start) >= timeout {
			t.Fatal("timed out waiting for the checkpoint update")
		}
		err = sleep.WithContext(ctx, 100*time.Millisecond)
		require.NoError(t, err)
	}

	assert.Equal(t, checkpoint, monCheckpoint)

	// Cancel context to stop monitor and exit all go routines
	cn()

	require.NoError(t, g.Wait())
}

type onReadyFunc func(ctx context.Context) error

func runNewSimpleMonitor(t *testing.T, ctx context.Context, index string, bulker bulk.Bulk, ch chan<- model.Action, onReady onReadyFunc) error {
	t.Helper()
	readyCh := make(chan error)
	mon, err := NewSimple(index, bulker.Client(), bulker.Client(),
		WithReadyChan(readyCh),
	)
	if err != nil {
		return err
	}
	return runSimpleMonitor(t, ctx, mon, readyCh, ch, onReady)
}

func runSimpleMonitor(t *testing.T, ctx context.Context, mon SimpleMonitor, readyCh chan error, ch chan<- model.Action, onReady onReadyFunc) error {
	t.Helper()

	g, ctx := errgroup.WithContext(ctx)

	monCtx, monCn := context.WithCancel(ctx)
	defer monCn()

	// Run monitor
	g.Go(func() error {
		return mon.Run(monCtx)
	})

	// Wait for monitor ready and call createActions
	err := <-readyCh
	if err != nil {
		return err
	}
	if onReady != nil {
		err = onReady(ctx)
		if err != nil {
			return err
		}
	}

	// Listen for monitor notifications, exit when received all the actions
	g.Go(func() error {
		// Cancel/stop monitor on exit
		defer monCn()
		for {
			select {
			case hits := <-mon.Output():
				for _, hit := range hits {
					var action model.Action
					err := hit.Unmarshal(&action)
					if err != nil {
						return err
					}
					ch <- action
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	return g.Wait()
}

func runSimpleMonitorTest(t *testing.T, ctx context.Context, index string, bulker bulk.Bulk) {
	ctx, cn := context.WithCancel(ctx)
	defer cn()

	g, ctx := errgroup.WithContext(ctx)

	var createdActions []model.Action
	ch := make(chan model.Action)
	g.Go(func() error {
		return runNewSimpleMonitor(t, ctx, index, bulker, ch, func(ctx context.Context) error {
			var err error
			createdActions, err = ftesting.StoreRandomActions(ctx, bulker, index, 1, 7)
			return err
		})
	})

	var gotActions []model.Action
	g.Go(func() error {
		defer cn()
		for a := range ch {
			gotActions = append(gotActions, a)
			if len(createdActions) == len(gotActions) {
				return nil
			}
		}
		return nil
	})

	require.NoError(t, g.Wait())

	// Need to set the seqno that are known only after the documents where indexed
	// in order to compare the slices of structs as a whole
	for i, a := range gotActions {
		createdActions[i].SeqNo = a.SeqNo
	}

	assert.Equal(t, createdActions, gotActions)
}
