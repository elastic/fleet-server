// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package monitor

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
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
)

func TestSimpleMonitorEmptyIndex(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetActions)

	runSimpleMonitorTest(t, ctx, index, bulker)
}

func TestSimpleMonitorNonEmptyIndex(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker, _ := ftesting.SetupActions(ctx, t, 1, 12)

	runSimpleMonitorTest(t, ctx, index, bulker)
}

func TestSimpleMonitorCheckpointOutOfSync(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker, _ := ftesting.SetupActions(ctx, t, 1, 12)

	g, ctx := errgroup.WithContext(ctx)

	var createdActions []model.Action
	ch := make(chan model.Action, 0)
	readyCh := make(chan error)
	mon, err := NewSimple(index, bulker.Client(), bulker.Client(),
		WithReadyChan(readyCh),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	g.Go(func() error {
		return runSimpleMonitor(t, ctx, mon, readyCh, index, bulker, ch, func(ctx context.Context) error {
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
		return nil
	})

	// Wait until actions are created
	wg.Wait()

	var checkpoint, monCheckpoint sqn.SeqNo
	checkpoint, err = gcheckpt.Query(ctx, bulker.Client(), index)
	require.NoError(t, err)

	log.Debug().Int64("checkpoint", checkpoint.Value()).Msg("checkpoint before test action delete")

	// Delete an action to emulate the gap between the fleet server tracking checkpoint and the index checkpoint
	// The delete causes the checkpoint increment and the fleet-server was not updating it's checkpoint tracked value correctly
	// in these cases.
	idx := len(createdActions) - 1
	err = bulker.Delete(ctx, index, createdActions[idx].Id, bulk.WithRefresh())
	require.NoError(t, err)

	checkpoint, err = gcheckpt.Query(ctx, bulker.Client(), index)
	require.NoError(t, err)
	log.Debug().Int64("checkpoint", checkpoint.Value()).Msg("checkpoint after test action delete")

	// Wait for fleet server monitor checkpoint to be incremented after delete
	m, _ := mon.(*simpleMonitorT)
	timeout := 10 * time.Second // This should not take that long, can wait until the test times out or shorter like this
	start := time.Now()
	for {
		monCheckpoint = m.loadCheckpoint()
		log.Debug().Int64("wait checkpoint", checkpoint.Value()).Int64("got checkpoint", monCheckpoint.Value()).Msg("monitor checkpoint")
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
	return runSimpleMonitor(t, ctx, mon, readyCh, index, bulker, ch, onReady)
}

func runSimpleMonitor(t *testing.T, ctx context.Context, mon SimpleMonitor, readyCh chan error, index string, bulker bulk.Bulk, ch chan<- model.Action, onReady onReadyFunc) error {
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
		return nil
	})

	return g.Wait()
}

func runSimpleMonitorTest(t *testing.T, ctx context.Context, index string, bulker bulk.Bulk) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	g, ctx := errgroup.WithContext(ctx)

	var createdActions []model.Action
	ch := make(chan model.Action, 0)
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
