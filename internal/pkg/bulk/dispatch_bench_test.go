// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"testing"
)

// BenchmarkDispatchAbortQueue measures allocation behavior when dispatch aborts
// in Phase 1 (blk never enqueued) due to context cancellation. This simulates
// the scenario where agents disconnect while their checkin request is waiting
// to enter the bulk engine's channel.
func BenchmarkDispatchAbortQueue(b *testing.B) {
	bulker := NewBulker(nil, nil, WithBlockQueueSize(1))

	// Fill the queue so dispatch always blocks in Phase 1.
	bulker.ch <- &bulkT{ch: make(chan respT, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so dispatch aborts immediately

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		blk := bulker.newBlk(ActionSearch, optionsT{})
		blk.buf.WriteString(`{"index":"test"}`)
		bulker.dispatch(ctx, blk)
	}
}

// BenchmarkDispatchAbortResponse measures the per-dispatch allocation cost
// when dispatch aborts in Phase 2 (blk enqueued, waiting for response) due
// to context cancellation. The drain goroutine is spawned but its cleanup
// (freeBlk) is async and does not affect alloc counts reported here.
// See TestDispatchAbortResponseDrainsAndFreesBlk for verification that the
// drain completes correctly.
func BenchmarkDispatchAbortResponse(b *testing.B) {
	bulker := NewBulker(nil, nil, WithBlockQueueSize(b.N+1))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so Phase 2 aborts immediately

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		blk := bulker.newBlk(ActionSearch, optionsT{})
		blk.buf.WriteString(`{"index":"test"}`)
		bulker.dispatch(ctx, blk)
	}
}

// BenchmarkDispatchSuccess measures allocation behavior on the success path
// for comparison with the abort benchmarks.
func BenchmarkDispatchSuccess(b *testing.B) {
	bulker := NewBulker(nil, nil, WithBlockQueueSize(1))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		blk := bulker.newBlk(ActionSearch, optionsT{})
		blk.buf.WriteString(`{"index":"test"}`)

		// Simulate the Run loop: drain channel and respond.
		go func() {
			item := <-bulker.ch
			item.ch <- respT{}
		}()

		resp := bulker.dispatch(context.Background(), blk)
		if resp.err != nil {
			b.Fatal(resp.err)
		}
		bulker.freeBlk(blk)
	}
}
