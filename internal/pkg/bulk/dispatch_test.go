// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDispatchAbortQueueFreesBlk(t *testing.T) {
	// When dispatch aborts in Phase 1 (blk never enqueued), blk must be freed
	// back to the pool so it can be reused.
	b := NewBulker(nil, nil, WithBlockQueueSize(1))

	// Fill the queue so dispatch blocks in Phase 1.
	b.ch <- &bulkT{ch: make(chan respT, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	blk := b.newBlk(ActionSearch, optionsT{})
	blk.buf.WriteString(`{"index":"test"}`)

	resp := b.dispatch(ctx, blk)
	require.Error(t, resp.err, "expected error from cancelled context")

	// blk should have been returned to the pool. Getting from the pool should
	// return the same (reset) object without a new allocation.
	reused := b.blkPool.Get().(*bulkT)
	require.Zero(t, reused.buf.Len(), "expected reused blk to have reset buf")
	require.Zero(t, reused.action, "expected reused blk to have reset action")
}

func TestDispatchAbortResponseDrainsAndFreesBlk(t *testing.T) {
	// When dispatch aborts in Phase 2 (blk enqueued, waiting for response),
	// a drain goroutine should wait for the flush response and then free blk.
	b := NewBulker(nil, nil, WithBlockQueueSize(1))

	ctx, cancel := context.WithCancel(context.Background())

	blk := b.newBlk(ActionSearch, optionsT{})
	blk.buf.WriteString(`{"index":"test"}`)

	// Drain the Run loop channel so dispatch can enqueue.
	go func() {
		<-b.ch
		// Don't respond yet — let dispatch enter Phase 2.
	}()

	// Let dispatch enqueue, then cancel context to trigger Phase 2 abort.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	resp := b.dispatch(ctx, blk)
	require.Error(t, resp.err, "expected error from cancelled context")

	// Now simulate the Run loop sending a response. This should unblock
	// the drain goroutine, which will call freeBlk.
	blk.ch <- respT{}

	// Give the drain goroutine time to complete.
	time.Sleep(50 * time.Millisecond)

	// blk should have been returned to the pool.
	reused := b.blkPool.Get().(*bulkT)
	require.Zero(t, reused.buf.Len(), "expected reused blk to have reset buf")
}

func TestDispatchSuccess(t *testing.T) {
	b := NewBulker(nil, nil, WithBlockQueueSize(1))

	ctx := context.Background()
	blk := b.newBlk(ActionSearch, optionsT{})
	blk.buf.WriteString(`{"index":"test"}`)

	// Simulate a fast ES response: send response before timeout.
	go func() {
		item := <-b.ch
		item.ch <- respT{data: nil, err: nil}
	}()

	resp := b.dispatch(ctx, blk)
	require.NoError(t, resp.err)
}
