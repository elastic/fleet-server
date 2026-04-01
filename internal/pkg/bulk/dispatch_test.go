// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDispatchTimeoutQueue(t *testing.T) {
	// Create a bulker with a tiny dispatch timeout and a full queue (size 1).
	b := NewBulker(nil, nil, WithBlockQueueSize(1))
	b.opts.dispatchTimeout = 50 * time.Millisecond

	// Fill the queue so the next dispatch blocks.
	b.ch <- &bulkT{}

	ctx := context.Background()
	blk := &bulkT{action: ActionSearch, ch: make(chan respT, 1)}

	start := time.Now()
	resp := b.dispatch(ctx, blk)
	elapsed := time.Since(start)

	if !errors.Is(resp.err, errDispatchTimeout) {
		t.Fatalf("expected errDispatchTimeout, got: %v", resp.err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("dispatch took too long: %v, expected ~50ms", elapsed)
	}
}

func TestDispatchTimeoutResponse(t *testing.T) {
	// Create a bulker with a tiny dispatch timeout and an empty queue (size 1).
	b := NewBulker(nil, nil, WithBlockQueueSize(1))
	b.opts.dispatchTimeout = 50 * time.Millisecond

	ctx := context.Background()
	blk := &bulkT{action: ActionSearch, ch: make(chan respT, 1)}

	// Queue is empty so dispatch enqueues successfully, then blocks waiting for response.
	start := time.Now()
	resp := b.dispatch(ctx, blk)
	elapsed := time.Since(start)

	if !errors.Is(resp.err, errDispatchTimeout) {
		t.Fatalf("expected errDispatchTimeout, got: %v", resp.err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("dispatch took too long: %v, expected ~50ms", elapsed)
	}
}

func TestDispatchSuccessBeforeTimeout(t *testing.T) {
	b := NewBulker(nil, nil, WithBlockQueueSize(1))
	b.opts.dispatchTimeout = 5 * time.Second

	ctx := context.Background()
	blk := &bulkT{action: ActionSearch, ch: make(chan respT, 1)}

	// Simulate a fast ES response: send response before timeout.
	go func() {
		// Wait for blk to be enqueued, then respond.
		item := <-b.ch
		item.ch <- respT{data: nil, err: nil}
	}()

	resp := b.dispatch(ctx, blk)
	if resp.err != nil {
		t.Fatalf("expected no error, got: %v", resp.err)
	}
}
