// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package monitor

import (
	"context"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestMonitorEmptyIndex(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := setupIndex(ctx, t)
	runMonitorTest(t, ctx, index, bulker)
}

func TestMonitorNonEmptyIndex(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker, _ := ftesting.SetupActions(ctx, t, 1, 12)
	runMonitorTest(t, ctx, index, bulker)
}

func runMonitorTest(t *testing.T, ctx context.Context, index string, bulker bulk.Bulk) {
	readyCh := make(chan error)
	mon, err := New(index, bulker.Client(), bulker.Client(),
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
		if merr == context.Canceled {
			merr = nil
		}
	}()

	// Wait until monitor is running
	err = <-readyCh
	require.NoError(t, err)

	// Create subscriptions before creating the actions, otherwise they can be missed
	subs := []Subscription{
		mon.Subscribe(),
		mon.Subscribe(),
		mon.Subscribe(), // no goroutine will read from the output
	}

	// Create random actions
	actions, err := ftesting.StoreRandomActions(ctx, bulker, index, 1, 7)
	require.NoError(t, err)

	gotActions := make([][]model.Action, 2)
	// Listen monitor updates
	var mwg sync.WaitGroup
	mwg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int, s Subscription) {
			defer mwg.Done()
			defer mon.Unsubscribe(s)
			for {
				select {
				case hits := <-s.Output():
					for _, hit := range hits {
						var action model.Action
						er := hit.Unmarshal(&action)
						require.NoError(t, er)
						gotActions[i] = append(gotActions[i], action)
						if len(gotActions[i]) == len(actions) {
							return
						}
					}
				case <-ctx.Done():
					return
				}
			}
		}(i, subs[i])
	}
	mon.Unsubscribe(subs[2]) // unsubscribe (nothing read from the channel)
	mwg.Wait()

	// Need to set the seqno that are known only after the documents where indexed
	// in order to compare the slices of structs as a whole
	for i, a := range gotActions[0] {
		actions[i].SeqNo = a.SeqNo
	}

	// The documents should be the same and in the same order
	diff := cmp.Diff(actions, gotActions[0])
	if diff != "" {
		t.Fatal(diff)
	}
	diff = cmp.Diff(actions, gotActions[1])
	if diff != "" {
		t.Fatal(diff)
	}

	// Stop monitor and wait for clean exit
	mcn()
	wg.Wait()
	require.NoError(t, merr)
}
