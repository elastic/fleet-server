// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDispatchRejectsWhenLimitReached(t *testing.T) {
	var limit int64 = 2
	b := NewBulker(nil, nil, WithBlockQueueSize(int(limit)+1), WithMaxPendingBulkDispatches(limit))

	// Fill the queue so dispatches block in Phase 1.
	for i := int64(0); i < limit; i++ {
		b.ch <- &bulkT{ch: make(chan respT, 1)}
	}

	var wg sync.WaitGroup

	// Saturate the pending bulk dispatch limit with goroutines blocked on the full channel.
	for i := int64(0); i < limit; i++ {
		blk := b.newBlk(ActionSearch, optionsT{})
		_, err := blk.buf.WriteString(`{"index":"test"}`)
		require.NoError(t, err)
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.dispatch(context.Background(), blk)
		}()
	}

	// Give the goroutines time to enter dispatch and increment the counter.
	// They'll block on the channel send since it's full.
	for b.pendingBulkDispatches.Load() < limit {
		// spin until both goroutines are pending
	}

	// The next dispatch should be rejected immediately.
	blk := b.newBlk(ActionSearch, optionsT{})
	_, err := blk.buf.WriteString(`{"index":"test"}`)
	require.NoError(t, err)
	resp := b.dispatch(context.Background(), blk)

	require.ErrorIs(t, resp.err, ErrTooManyBulkDispatches)

	// Clean up: drain the channel to unblock the goroutines.
	for i := int64(0); i < limit; i++ {
		<-b.ch // remove the filler items
	}
	for i := int64(0); i < limit; i++ {
		item := <-b.ch // receive the dispatch items
		item.ch <- respT{}
	}
	wg.Wait()
}

func TestDispatchAllowsWhenUnderLimit(t *testing.T) {
	b := NewBulker(nil, nil, WithBlockQueueSize(1), WithMaxPendingBulkDispatches(10))

	blk := b.newBlk(ActionSearch, optionsT{})
	_, err := blk.buf.WriteString(`{"index":"test"}`)
	require.NoError(t, err)

	// Simulate the Run loop responding.
	go func() {
		item := <-b.ch
		item.ch <- respT{}
	}()

	resp := b.dispatch(context.Background(), blk)
	require.NoError(t, resp.err)

	// Counter should be back to 0 after dispatch completes.
	require.Equal(t, int64(0), b.pendingBulkDispatches.Load())
}

func TestDispatchNoLimitWhenZero(t *testing.T) {
	// With maxPendingBulkDispatches=0, there should be no limit enforced.
	b := NewBulker(nil, nil, WithBlockQueueSize(1), WithMaxPendingBulkDispatches(0))

	blk := b.newBlk(ActionSearch, optionsT{})
	_, err := blk.buf.WriteString(`{"index":"test"}`)
	require.NoError(t, err)

	go func() {
		item := <-b.ch
		item.ch <- respT{}
	}()

	resp := b.dispatch(context.Background(), blk)
	require.NoError(t, resp.err)

	// Counter should not have been touched (0 means disabled).
	require.Equal(t, int64(0), b.pendingBulkDispatches.Load())
}
