// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package monitor

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
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

func runSimpleMonitorTest(t *testing.T, ctx context.Context, index string, bulker bulk.Bulk) {
	readyCh := make(chan error)
	mon, err := NewSimple(index, bulker.Client(), bulker.Client(),
		WithReadyChan(readyCh),
	)
	require.NoError(t, err)

	// Start monitor
	var wg sync.WaitGroup
	mctx, mcn := context.WithCancel(ctx)
	var merr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		merr = mon.Run(mctx)
		if errors.Is(merr, context.Canceled) {
			merr = nil
		}
	}()

	// Wait until monitor is running
	err = <-readyCh
	require.NoError(t, err)

	// Create random actions
	actions, err := ftesting.StoreRandomActions(ctx, bulker, index, 1, 7)
	require.NoError(t, err)

	var gotActions []model.Action
	// Listen monitor updates
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		for {
			select {
			case hits := <-mon.Output():
				for _, hit := range hits {
					var action model.Action
					er := hit.Unmarshal(&action)
					require.NoError(t, er)
					gotActions = append(gotActions, action)
					if len(gotActions) == len(actions) {
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	mwg.Wait()

	// Need to set the seqno that are known only after the documents where indexed
	// in order to compare the slices of structs as a whole
	for i, a := range gotActions {
		actions[i].SeqNo = a.SeqNo
	}

	// The documents should be the same and in the same order
	diff := cmp.Diff(actions, gotActions)
	if diff != "" {
		t.Fatal(diff)
	}

	// Stop monitor and wait for clean exit
	mcn()
	wg.Wait()
	require.NoError(t, merr)

}
