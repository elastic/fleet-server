// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"sync"
	"testing"
)

func TestDispatchRejectsWhenLimitReached(t *testing.T) {
	limit := 2
	b := NewBulker(nil, nil, WithBlockQueueSize(limit+1), WithMaxPendingDispatches(limit))

	// Fill the queue so dispatches block in Phase 1.
	for i := 0; i < limit; i++ {
		b.ch <- &bulkT{ch: make(chan respT, 1)}
	}

	var wg sync.WaitGroup

	// Saturate the pending dispatch limit with goroutines blocked on the full channel.
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blk := b.newBlk(ActionSearch, optionsT{})
			blk.buf.WriteString(`{"index":"test"}`)
			b.dispatch(context.Background(), blk)
		}()
	}

	// Give the goroutines time to enter dispatch and increment the counter.
	// They'll block on the channel send since it's full.
	for b.pendingDispatches.Load() < int64(limit) {
		// spin until both goroutines are pending
	}

	// The next dispatch should be rejected immediately.
	blk := b.newBlk(ActionSearch, optionsT{})
	blk.buf.WriteString(`{"index":"test"}`)
	resp := b.dispatch(context.Background(), blk)

	if resp.err != ErrTooManyDispatches {
		t.Fatalf("expected ErrTooManyDispatches, got: %v", resp.err)
	}

	// Clean up: drain the channel to unblock the goroutines.
	for i := 0; i < limit; i++ {
		<-b.ch // remove the filler items
	}
	for i := 0; i < limit; i++ {
		item := <-b.ch // receive the dispatch items
		item.ch <- respT{}
	}
	wg.Wait()
}

func TestDispatchAllowsWhenUnderLimit(t *testing.T) {
	b := NewBulker(nil, nil, WithBlockQueueSize(1), WithMaxPendingDispatches(10))

	blk := b.newBlk(ActionSearch, optionsT{})
	blk.buf.WriteString(`{"index":"test"}`)

	// Simulate the Run loop responding.
	go func() {
		item := <-b.ch
		item.ch <- respT{}
	}()

	resp := b.dispatch(context.Background(), blk)
	if resp.err != nil {
		t.Fatalf("expected no error, got: %v", resp.err)
	}

	// Counter should be back to 0 after dispatch completes.
	if pending := b.pendingDispatches.Load(); pending != 0 {
		t.Fatalf("expected 0 pending dispatches, got: %d", pending)
	}
}

func TestDispatchNoLimitWhenZero(t *testing.T) {
	// With maxPendingDispatches=0, there should be no limit enforced.
	b := NewBulker(nil, nil, WithBlockQueueSize(1), WithMaxPendingDispatches(0))

	blk := b.newBlk(ActionSearch, optionsT{})
	blk.buf.WriteString(`{"index":"test"}`)

	go func() {
		item := <-b.ch
		item.ch <- respT{}
	}()

	resp := b.dispatch(context.Background(), blk)
	if resp.err != nil {
		t.Fatalf("expected no error, got: %v", resp.err)
	}

	// Counter should not have been touched (0 means disabled).
	if pending := b.pendingDispatches.Load(); pending != 0 {
		t.Fatalf("expected 0 pending dispatches, got: %d", pending)
	}
}
