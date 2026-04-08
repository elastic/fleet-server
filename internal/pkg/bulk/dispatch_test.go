// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDispatchAbortQueueFreesBlk(t *testing.T) {
	// When dispatch aborts in its first select() (blk never enqueued),
	// blk must be freed back to the pool so it can be reused.
	b := NewBulker(nil, nil, WithBlockQueueSize(1))

	// Fill the queue so dispatch blocks in its first select().
	b.ch <- &bulkT{ch: make(chan respT, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	// Pre-cancel so the first select() deterministically aborts and blk
	// is never enqueued.
	cancel()

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

func TestDispatchAbortResponseReachesSecondSelect(t *testing.T) {
	// When dispatch aborts in its second select() (blk enqueued, waiting
	// for response), it must return ctx.Err() after the Run loop has
	// already taken the blk.
	b := NewBulker(nil, nil, WithBlockQueueSize(1))

	ctx, cancel := context.WithCancel(context.Background())

	blk := b.newBlk(ActionSearch, optionsT{})
	blk.buf.WriteString(`{"index":"test"}`)

	// Drain b.ch and signal once dispatch has enqueued. After this signal,
	// dispatch is guaranteed to be in (or about to enter) its second
	// select(), so cancelling ctx now deterministically triggers the
	// abort from that select().
	enqueued := make(chan struct{})
	go func() {
		<-b.ch
		close(enqueued)
	}()

	// Run dispatch in a goroutine so we can cancel its ctx after it has
	// crossed into the second select().
	respCh := make(chan respT, 1)
	go func() {
		respCh <- b.dispatch(ctx, blk)
	}()

	<-enqueued
	cancel()

	resp := <-respCh
	require.ErrorIs(t, resp.err, context.Canceled)

	// Unblock the drain goroutine that dispatch spawned so it doesn't
	// linger past the test.
	blk.ch <- respT{}
}

func TestDrainAndFreeAbortedBlkResponse(t *testing.T) {
	// When the Run loop delivers a response to an abandoned blk,
	// drainAndFreeAbortedBlk must free it (which resets its fields and
	// returns it to the pool).
	b := NewBulker(nil, nil, WithBlockQueueSize(1))

	blk := b.newBlk(ActionSearch, optionsT{})
	blk.buf.WriteString(`{"index":"test"}`)
	require.NotZero(t, blk.action)
	require.NotZero(t, blk.buf.Len())

	// Simulate the Run loop's late response before the drain runs. blk.ch
	// is buffered cap 1, so this send does not block.
	blk.ch <- respT{}

	// Run synchronously so blk is only touched by this goroutine, making
	// the post-drain field reads race-free.
	//
	// blk.reset() is only called from freeBlk, so observing the reset
	// below proves freeBlk ran.
	b.drainAndFreeAbortedBlk(blk)

	require.Zero(t, blk.action)
	require.Zero(t, blk.buf.Len())
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
