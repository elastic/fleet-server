// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/mailru/easyjson"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"
)

func (b *Bulker) Search(ctx context.Context, index string, body []byte, opts ...Opt) (*es.ResultT, error) {
	span, ctx := apm.StartSpan(ctx, bulkSpanNames[ActionSearch], "bulker")
	defer span.End()
	opt := b.parseOpts(opts...)
	if tx := apm.TransactionFromContext(ctx); tx != nil {
		tCtx := tx.TraceContext()
		opt.spanLink = apm.SpanLink{Trace: tCtx.Trace, Span: tCtx.Span}
		opt.hasSpanLink = true
	}
	action := ActionSearch

	// Use /_fleet/_fleet_msearch fleet plugin endpoint if need to wait for checkpoints
	if len(opt.WaitForCheckpoints) > 0 {
		action = ActionFleetSearch
	}
	blk := b.newBlk(action, opt)

	// Serialize request
	const kSlop = 64
	blk.buf.Grow(len(body) + kSlop)

	if err := b.writeMsearchMeta(&blk.buf, index, opt.Indices, opt.WaitForCheckpoints, opt.IgnoreUnavailable); err != nil {
		return nil, err
	}

	if err := b.writeMsearchBody(&blk.buf, body); err != nil {
		return nil, err
	}

	// Process response
	resp := b.dispatch(ctx, blk)
	if resp.err != nil {
		return nil, resp.err
	}
	b.freeBlk(blk)

	// TODO if we can ever set span links after creation we can inject the flushQueue span into resp and link to the action span here.

	// Interpret response
	r, ok := resp.data.(*MsearchResponseItem)
	if !ok {
		return nil, fmt.Errorf("unable to cast response as type *MsearchResponseItem, detected type: %T", resp.data)
	}
	return &es.ResultT{HitsT: r.Hits, Aggregations: r.Aggregations}, nil
}

func (b *Bulker) writeMsearchMeta(buf *Buf, index string, moreIndices []string, checkpoints []int64, ignoreUnavailble bool) error {
	if err := b.validateIndex(index); err != nil {
		return err
	}

	needComma := true

	_, _ = buf.WriteString("{")

	if len(moreIndices) > 0 {
		if err := b.validateIndices(moreIndices); err != nil {
			return err
		}

		indices := make([]string, 0, 1+len(moreIndices))
		indices = append(indices, index)
		indices = append(indices, moreIndices...)

		_, _ = buf.WriteString(`"index": `)
		if d, err := json.Marshal(indices); err != nil {
			return err
		} else {
			_, _ = buf.Write(d)
		}
	} else if index != "" {
		_, _ = buf.WriteString(`"index": "`)
		_, _ = buf.WriteString(index)
		_, _ = buf.WriteString("\"")
	} else {
		needComma = false
	}

	if ignoreUnavailble {
		if needComma {
			_, _ = buf.WriteString(`,`)
		}
		_, _ = buf.WriteString(`"ignore_unavailable": true`)
		needComma = true
	}

	if len(checkpoints) > 0 {
		if needComma {
			_, _ = buf.WriteString(`,`)
		}
		_, _ = buf.WriteString(` "wait_for_checkpoints": `)
		// Write array as string, example: [1,2,3]
		_, _ = buf.WriteString(sqn.SeqNo(checkpoints).JSONString())
	}

	_, _ = buf.WriteString("}\n")

	return nil
}

func (b *Bulker) writeMsearchBody(buf *Buf, body []byte) error {
	_, _ = buf.Write(body)
	_, _ = buf.WriteRune('\n')

	return b.validateBody(body)
}

func (b *Bulker) flushSearch(ctx context.Context, queue queueT) error {
	start := time.Now()

	const kRoughEstimatePerItem = 256

	bufSz := max(queue.cnt*kRoughEstimatePerItem, queue.pending)

	buf := b.flushBufPool.Get().(*bytes.Buffer) //nolint:errcheck // we control what is placed in the pool
	buf.Reset()
	buf.Grow(bufSz)
	defer b.flushBufPool.Put(buf)

	queueCnt := 0
	links := make([]apm.SpanLink, 0, queue.cnt)
	for n := queue.head; n != nil; n = n.next {
		buf.Write(n.buf.Bytes())
		queueCnt += 1
		if n.hasSpanLink {
			links = append(links, n.spanLink)
		}
	}
	if len(links) == 0 {
		links = nil
	}
	span, ctx := apm.StartSpanOptions(ctx, flushSpanNames[queue.ty], queue.Type(), apm.SpanOptions{
		Links: links,
	})
	defer span.End()

	// Do actual bulk request; and send response on chan
	var (
		res *esapi.Response
		err error
	)

	if queue.ty == kQueueFleetSearch {
		req := esapi.FleetMsearchRequest{
			Body: bytes.NewReader(buf.Bytes()),
		}
		res, err = req.Do(ctx, b.es)
	} else {
		req := esapi.MsearchRequest{
			Body: bytes.NewReader(buf.Bytes()),
		}
		res, err = req.Do(ctx, b.es)
	}

	if err != nil {
		return err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		zerolog.Ctx(ctx).Warn().Str("mod", kModBulk).Str("error.message", res.String()).Msg("bulker.flushSearch: Fail writeMsearchBody")
		return parseError(res, zerolog.Ctx(ctx))
	}

	// Reuse buffer
	buf.Reset()

	bodySz, err := buf.ReadFrom(res.Body)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Str("mod", kModBulk).Msg("MsearchResponse error")
		return err
	}

	// prealloc slice
	var blk MsearchResponse
	blk.Responses = make([]MsearchResponseItem, 0, queueCnt)

	if err = easyjson.Unmarshal(buf.Bytes(), &blk); err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Str("mod", kModBulk).Msg("Unmarshal error")
		return err
	}

	zerolog.Ctx(ctx).Trace().
		Err(err).
		Str("mod", kModBulk).
		Dur("rtt", time.Since(start)).
		Int("took", blk.Took).
		Int("cnt", len(blk.Responses)).
		Int("bufSz", bufSz).
		Int64("bodySz", bodySz).
		Msg("flushSearch")

	if len(blk.Responses) != queueCnt {
		return fmt.Errorf("Bulk queue length mismatch")
	}

	// WARNING: Once we start pushing items to
	// the queue, the node pointers are invalid.
	// Do NOT return a non-nil value or failQueue
	// up the stack will fail.

	n := queue.head
	for i := range blk.Responses {
		next := n.next // 'n' is invalid immediately on channel send

		response := &blk.Responses[i]

		select {
		case n.ch <- respT{
			err:  response.deriveError(),
			idx:  n.idx,
			data: response,
		}:
		default:
			panic("Unexpected blocked response channel on flushSearch")
		}
		n = next
	}

	return nil
}

// flushEnrollSearch handles the kQueueEnrollSearch queue. It:
//  1. Groups items by dedupeKey — oldest (FIFO) occurrence is canonical, the rest are duplicates.
//  2. Refreshes all unique refreshIndex values in the batch.
//  3. Sends an msearch containing only the canonical items.
//  4. Dispatches results to canonical items; sends ErrEnrollDuplicate to duplicates (or the
//     canonical's error if the search itself failed, to avoid hiding operational failures).
func (b *Bulker) flushEnrollSearch(ctx context.Context, queue queueT) error {
	// Collect items in LIFO order from the queue (queue.head is newest), then reverse to FIFO
	// so the oldest request becomes canonical for each dedupeKey.
	var all []*bulkT
	for n := queue.head; n != nil; n = n.next {
		all = append(all, n)
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}

	// Group items: oldest occurrence of each dedupeKey is canonical, rest are dupes.
	dupesByKey := make(map[string][]*bulkT)
	var canonicals []*bulkT
	for _, n := range all {
		key := n.dedupeKey
		if _, seen := dupesByKey[key]; !seen {
			dupesByKey[key] = nil // mark key as seen; nil slice = no dupes yet
			canonicals = append(canonicals, n)
		} else {
			dupesByKey[key] = append(dupesByKey[key], n)
		}
	}

	if len(canonicals) == 0 {
		return nil
	}

	// Refresh all unique indices in the batch before searching so retries see the most recent writes.
	refreshIndices := make(map[string]struct{})
	for _, n := range canonicals {
		if n.refreshIndex != "" {
			refreshIndices[n.refreshIndex] = struct{}{}
		}
	}
	if len(refreshIndices) > 0 {
		idxSlice := make([]string, 0, len(refreshIndices))
		for idx := range refreshIndices {
			idxSlice = append(idxSlice, idx)
		}
		refreshResp, err := esapi.IndicesRefreshRequest{Index: idxSlice}.Do(ctx, b.es)
		if err != nil {
			failQueue(queue, err)
			return nil
		}
		if refreshResp.Body != nil {
			refreshResp.Body.Close()
		}
		if refreshResp.IsError() {
			err = fmt.Errorf("enroll search refresh failed: %s", refreshResp.String())
			failQueue(queue, err)
			return nil
		}
	}

	// Build msearch body from canonical items only.
	const kRoughEstimatePerItem = 256
	bufSz := max(len(canonicals)*kRoughEstimatePerItem, queue.pending)
	buf := b.flushBufPool.Get().(*bytes.Buffer) //nolint:errcheck
	buf.Reset()
	buf.Grow(bufSz)
	defer b.flushBufPool.Put(buf)

	for _, n := range canonicals {
		buf.Write(n.buf.Bytes())
	}

	span, ctx := apm.StartSpanOptions(ctx, flushSpanNames[queue.ty], queue.Type(), apm.SpanOptions{})
	defer span.End()

	msearchReq := esapi.MsearchRequest{Body: bytes.NewReader(buf.Bytes())}
	res, err := msearchReq.Do(ctx, b.es)
	if err != nil {
		failQueue(queue, err)
		return nil
	}
	if res.Body != nil {
		defer res.Body.Close()
	}
	if res.IsError() {
		err = parseError(res, zerolog.Ctx(ctx))
		failQueue(queue, err)
		return nil
	}

	buf.Reset()
	if _, err = buf.ReadFrom(res.Body); err != nil {
		return err
	}

	var blk MsearchResponse
	blk.Responses = make([]MsearchResponseItem, 0, len(canonicals))
	if err = easyjson.Unmarshal(buf.Bytes(), &blk); err != nil {
		return err
	}
	if len(blk.Responses) != len(canonicals) {
		return fmt.Errorf("enroll search queue length mismatch: got %d, want %d", len(blk.Responses), len(canonicals))
	}

	// WARNING: Once we start pushing items to the queue, the node pointers are invalid.
	for i, n := range canonicals {
		response := &blk.Responses[i]
		respErr := response.deriveError()
		select {
		case n.ch <- respT{err: respErr, idx: n.idx, data: response}:
		default:
			panic("Unexpected blocked response channel on flushEnrollSearch canonical")
		}
		// If the canonical's search itself failed, propagate that error to duplicates
		// instead of ErrEnrollDuplicate so callers don't suppress real failures.
		dupeErr := ErrEnrollDuplicate
		if respErr != nil {
			dupeErr = respErr
		}
		for _, dupe := range dupesByKey[n.dedupeKey] {
			select {
			case dupe.ch <- respT{err: dupeErr}:
			default:
				panic("Unexpected blocked response channel on flushEnrollSearch dupe")
			}
		}
	}
	return nil
}
