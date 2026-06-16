// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"context"
	"errors"
	"math"

	"go.elastic.co/apm/v2"
)

// TODO: Are multi requests used by anything? a quick grep shows no hits outside the bulk package.

func (b *Bulker) MCreate(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error) {
	return b.multiWaitBulkOp(ctx, ActionCreate, ops)
}

func (b *Bulker) MIndex(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error) {
	return b.multiWaitBulkOp(ctx, ActionIndex, ops)
}

func (b *Bulker) MUpdate(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error) {
	return b.multiWaitBulkOp(ctx, ActionUpdate, ops)
}

func (b *Bulker) MDelete(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error) {
	return b.multiWaitBulkOp(ctx, ActionDelete, ops)
}

func (b *Bulker) multiWaitBulkOp(ctx context.Context, action actionT, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error) { //nolint:unparam // better to keep consistency with other methods
	if len(ops) == 0 {
		return nil, nil
	}

	if uint(len(ops)) > math.MaxUint32 {
		return nil, errors.New("too many bulk ops")
	}

	span, ctx := apm.StartSpan(ctx, bulkSpanNames[action], "bulker")
	defer span.End()
	opt := b.parseOpts(opts...)

	var spanLink apm.SpanLink
	hasSpanLink := false
	if tx := apm.TransactionFromContext(ctx); tx != nil {
		tCtx := tx.TraceContext()
		spanLink = apm.SpanLink{Trace: tCtx.Trace, Span: tCtx.Span}
		hasSpanLink = true
	}

	// Contract is that consumer never blocks, so must preallocate.
	// Could consider making the response channel *respT to limit memory usage.
	ch := make(chan respT, len(ops))

	actionStr := action.String()

	// O(n) Determine how much space we need
	var byteCnt int
	for _, op := range ops {
		byteCnt += b.calcBulkSz(actionStr, op.Index, op.ID, opt.RetryOnConflict, op.Body)
	}

	// Create one bulk buffer to serialize each piece.
	// This decreases pressure on the heap. If we calculculate wrong,
	// the Buf objectect has the property that previously cached slices
	// are still valid.  However, underestimating the buffer size
	// can lead to multiple copies, which undermines the optimization.
	var bulkBuf Buf
	bulkBuf.Grow(byteCnt)

	// Serialize requests
	bulks := make([]bulkT, len(ops))
	for i := range ops {

		bufIdx := bulkBuf.Len()

		op := &ops[i]

		if err := b.writeBulkMeta(&bulkBuf, actionStr, op.Index, op.ID, opt.RetryOnConflict); err != nil {
			return nil, err
		}

		if err := b.writeBulkBody(&bulkBuf, action, op.Body); err != nil {
			return nil, err
		}

		bodySlice := bulkBuf.Bytes()[bufIdx:]

		bulk := &bulks[i]
		bulk.ch = ch
		bulk.idx = int32(i)
		bulk.action = action
		bulk.buf.Set(bodySlice)
		bulk.spanLink = spanLink
		bulk.hasSpanLink = hasSpanLink
		if opt.Refresh {
			bulk.flags.Set(flagRefresh)
		}
	}

	// Dispatch requests
	if err := b.multiDispatch(ctx, bulks); err != nil {
		return nil, err
	}

	// Wait for response and populate return slice
	var lastErr error
	items := make([]BulkIndexerResponseItem, len(ops))

	for range ops {
		select {
		case r := <-ch:
			if r.err != nil {
				lastErr = r.err
			}
			if r.data != nil {
				items[r.idx] = *r.data.(*BulkIndexerResponseItem) //nolint:errcheck // response data type is guaranteed by the bulk engine
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return items, lastErr
}

func (b *Bulker) multiDispatch(ctx context.Context, blks []bulkT) error {

	// Dispatch to bulk Run loop; Iterate by reference.
	for i := range blks {
		select {
		case b.ch <- &blks[i]:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
