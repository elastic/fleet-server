// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	for range limit {
		b.ch <- &bulkT{ch: make(chan respT, 1)}
	}

	var wg sync.WaitGroup

	// Saturate the pending bulk dispatch limit with goroutines blocked on the full channel.
	for range limit {
		blk := b.newBlk(ActionSearch, optionsT{})
		_, err := blk.buf.WriteString(`{"index":"test"}`)
		require.NoError(t, err)
		wg.Go(func() {
			b.dispatch(context.Background(), blk)
		})
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
	for range limit {
		<-b.ch // remove the filler items
	}
	for range limit {
		item := <-b.ch // receive the dispatch items
		item.ch <- respT{}
	}
	wg.Wait()
}

func TestDispatchSucceedsWhenBelowLimit(t *testing.T) {
	tests := map[string]int64{
		"under limit":      10,
		"no limit when zero": 0,
	}
	for name, limit := range tests {
		t.Run(name, func(t *testing.T) {
			b := NewBulker(nil, nil, WithBlockQueueSize(1), WithMaxPendingBulkDispatches(limit))

			blk := b.newBlk(ActionSearch, optionsT{})
			_, err := blk.buf.WriteString(`{"index":"test"}`)
			require.NoError(t, err)

			go func() {
				item := <-b.ch
				item.ch <- respT{}
			}()

			resp := b.dispatch(context.Background(), blk)
			require.NoError(t, resp.err)

			require.Equal(t, int64(0), b.pendingBulkDispatches.Load())
		})
	}
}
