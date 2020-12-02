// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"bytes"
	"context"

	"github.com/rs/zerolog/log"
)

func (b *Bulker) MUpdate(ctx context.Context, ops []BulkOp, opts ...Opt) error {
	_, err := b.multiWaitBulkAction(ctx, ActionUpdate, ops)
	return err
}

func (b *Bulker) multiWaitBulkAction(ctx context.Context, action Action, ops []BulkOp, opts ...Opt) ([]BulkIndexerResponseItem, error) {
	opt := b.parseOpts(opts...)

	// Serialize requests
	nops := make([]BulkOp, 0, len(ops))
	for _, op := range ops {

		// Prealloc buffer
		const kSlop = 64
		var buf bytes.Buffer
		buf.Grow(len(op.Body) + kSlop)

		if err := b.writeBulkMeta(&buf, action, op.Index, op.Id); err != nil {
			return nil, err
		}

		if err := b.writeBulkBody(&buf, op.Body); err != nil {
			return nil, err
		}

		nops = append(nops, BulkOp{
			Id:    op.Id,
			Index: op.Index,
			Body:  buf.Bytes(),
		})
	}

	// Dispatch and wait for response
	resps, err := b.multiDispatch(ctx, action, opt, nops)
	if err != nil {
		return nil, err
	}

	items := make([]BulkIndexerResponseItem, len(resps))
	for i, r := range resps {
		if r.err != nil {
			// TODO: well this is not great; handle this better
			log.Error().Err(r.err).Msg("Fail muliDispatch")
			return nil, r.err
		}
		items[i] = *r.data.(*BulkIndexerResponseItem)
	}

	return items, nil
}

func (b *Bulker) multiDispatch(ctx context.Context, action Action, opts optionsT, ops []BulkOp) ([]respT, error) {
	var err error

	ch := make(chan respT, len(ops))

	for i, op := range ops {
		item := bulkT{
			i,
			action,
			ch,
			op.Body,
			opts,
		}

		// Dispatch to bulk Run loop
		select {
		case b.ch <- item:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Wait for response
	responses := make([]respT, 0, len(ops))

LOOP:
	for len(responses) < len(ops) {
		select {
		case resp := <-ch:
			responses = append(responses, resp)
		case <-ctx.Done():
			err = ctx.Err()
			responses = nil
			break LOOP
		}
	}

	return responses, err
}
