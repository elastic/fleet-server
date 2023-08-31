// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/mailru/easyjson"
	"github.com/rs/zerolog/log"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

func (b *Bulker) Create(ctx context.Context, index, id string, body []byte, opts ...Opt) (string, error) {
	item, err := b.waitBulkAction(ctx, ActionCreate, index, id, body, opts...)
	if err != nil {
		return "", err
	}

	return item.DocumentID, nil
}

func (b *Bulker) Index(ctx context.Context, index, id string, body []byte, opts ...Opt) (string, error) {
	item, err := b.waitBulkAction(ctx, ActionIndex, index, id, body, opts...)
	if err != nil {
		return "", err
	}
	return item.DocumentID, nil
}

func (b *Bulker) Update(ctx context.Context, index, id string, body []byte, opts ...Opt) error {
	_, err := b.waitBulkAction(ctx, ActionUpdate, index, id, body, opts...)
	return err
}

func (b *Bulker) Delete(ctx context.Context, index, id string, opts ...Opt) error {
	_, err := b.waitBulkAction(ctx, ActionDelete, index, id, nil, opts...)
	return err
}

func (b *Bulker) waitBulkAction(ctx context.Context, action actionT, index, id string, body []byte, opts ...Opt) (*BulkIndexerResponseItem, error) {
	opt := b.parseOpts(append(opts, withAPMLinkedContext(ctx))...)
	blk := b.newBlk(action, opt)

	// Serialize request
	const kSlop = 64
	blk.buf.Grow(len(body) + kSlop)

	if err := b.writeBulkMeta(&blk.buf, action.String(), index, id, opt.RetryOnConflict); err != nil {
		return nil, err
	}

	if err := b.writeBulkBody(&blk.buf, action, body); err != nil {
		return nil, err
	}

	if blk.setLinks {
		var span *apm.Span
		span, ctx = apm.StartSpanOptions(ctx, "action", action.String(), apm.SpanOptions{
			Links: []apm.SpanLink{blk.spanLinks},
		})
		defer span.End()
	}

	// Dispatch and wait for response
	resp := b.dispatch(ctx, blk)
	if resp.err != nil {
		return nil, resp.err
	}
	b.freeBlk(blk)

	r, ok := resp.data.(*BulkIndexerResponseItem)
	if !ok {
		return nil, fmt.Errorf("unable to cast to *BulkIndexerResponseItem, detected type %T", resp.data)
	}
	if err := es.TranslateError(r.Status, r.Error); err != nil {
		return nil, err
	}
	return r, nil
}

func (b *Bulker) writeMget(buf *Buf, index, id string) error {
	if err := b.validateMeta(index, id); err != nil {
		return err
	}

	_, _ = buf.WriteString(`{"_index":"`)
	_, _ = buf.WriteString(index)
	_, _ = buf.WriteString(`","_id":"`)
	_, _ = buf.WriteString(id)
	_, _ = buf.WriteString(`"},`)
	return nil
}

func (b *Bulker) writeBulkMeta(buf *Buf, action, index, id, retry string) error {
	if err := b.validateMeta(index, id); err != nil {
		return err
	}

	_, _ = buf.WriteString(`{"`)
	_, _ = buf.WriteString(action)
	_, _ = buf.WriteString(`":{`)
	if id != "" {
		_, _ = buf.WriteString(`"_id":"`)
		_, _ = buf.WriteString(id)
		_, _ = buf.WriteString(`",`)
	}
	if retry != "" {
		_, _ = buf.WriteString(`"retry_on_conflict":`)
		_, _ = buf.WriteString(retry)
		_, _ = buf.WriteString(`,`)
	}

	_, _ = buf.WriteString(`"_index":"`)
	_, _ = buf.WriteString(index)
	_, _ = buf.WriteString("\"}}\n")

	return nil
}

func (b *Bulker) writeBulkBody(buf *Buf, action actionT, body []byte) error {
	if len(body) == 0 {
		if action == ActionDelete {
			return nil
		}

		// Weird to index, create, or update empty, but will allow
		_, _ = buf.WriteString("{}\n")
		return nil
	}

	if err := b.validateBody(body); err != nil {
		return err
	}

	_, _ = buf.Write(body)
	_, _ = buf.WriteRune('\n')
	return nil
}

func (b *Bulker) calcBulkSz(action, idx, id, retry string, body []byte) int {
	const kFraming = 19
	metaSz := kFraming + len(action) + len(idx)

	if retry != "" {
		metaSz += 21 + len(retry)
	}

	var idSz int
	if id != "" {
		const kIDFraming = 9
		idSz = kIDFraming + len(id)
	}

	var bodySz int
	if len(body) != 0 {
		const kBodyFraming = 1
		bodySz = kBodyFraming + len(body)
	}

	return metaSz + idSz + bodySz
}

func (b *Bulker) flushBulk(ctx context.Context, queue queueT) error {
	start := time.Now()

	const kRoughEstimatePerItem = 200

	bufSz := queue.cnt * kRoughEstimatePerItem
	if bufSz < queue.pending {
		bufSz = queue.pending
	}

	var buf bytes.Buffer
	buf.Grow(bufSz)

	queueCnt := 0
	links := []apm.SpanLink{}
	for n := queue.head; n != nil; n = n.next {
		buf.Write(n.buf.Bytes())
		queueCnt += 1
		if n.setLinks {
			links = append(links, n.spanLinks)
		}
	}

	// Do actual bulk request; defer to the client
	req := esapi.BulkRequest{
		Body: bytes.NewReader(buf.Bytes()),
	}

	if queue.ty == kQueueRefreshBulk {
		req.Refresh = "true"
	}

	if len(links) > 0 {
		var span *apm.Span
		span, ctx = apm.StartSpanOptions(ctx, "flushQueue", queue.Type(), apm.SpanOptions{
			Links: links,
		})
		defer span.End()
	}

	res, err := req.Do(ctx, b.es)
	if err != nil {
		log.Error().Err(err).Str("mod", kModBulk).Msg("Fail BulkRequest req.Do")
		return err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		log.Error().Str("mod", kModBulk).Str("err", res.String()).Msg("Fail BulkRequest result")
		return parseError(res)
	}

	// Reuse buffer
	buf.Reset()

	bodySz, err := buf.ReadFrom(res.Body)
	if err != nil {
		log.Error().
			Err(err).
			Str("mod", kModBulk).
			Msg("Response error")
		return err
	}

	var blk bulkIndexerResponse
	blk.Items = make([]bulkStubItem, 0, queueCnt)

	// TODO: We're loosing information abut the errors, we should check a way
	// to return the full error ES returns
	if err = easyjson.Unmarshal(buf.Bytes(), &blk); err != nil {
		log.Err(err).
			Str("mod", kModBulk).
			Msg("flushBulk failed, could not unmarshal ES response")
		return fmt.Errorf("flushBulk failed, could not unmarshal ES response: %w", err)
	}
	if blk.HasErrors {
		// We lack information to properly correlate this error with what has failed.
		// Thus, for now it'd be more noise than information outside an investigation.
		log.Debug().Err(errors.New(buf.String())).Msg("Bulk call: Es returned an error")
	}

	log.Trace().
		Err(err).
		Bool("refresh", queue.ty == kQueueRefreshBulk).
		Str("mod", kModBulk).
		Int("took", blk.Took).
		Dur("rtt", time.Since(start)).
		Bool("hasErrors", blk.HasErrors).
		Int("cnt", len(blk.Items)).
		Int("bufSz", bufSz).
		Int64("bodySz", bodySz).
		Msg("flushBulk")

	if len(blk.Items) != queueCnt {
		return fmt.Errorf("Bulk queue length mismatch")
	}

	// WARNING: Once we start pushing items to
	// the queue, the node pointers are invalid.
	// Do NOT return a non-nil value or failQueue
	// up the stack will fail.

	n := queue.head
	for i := range blk.Items {
		next := n.next // 'n' is invalid immediately on channel send

		item := blk.Items[i].Choose()
		select {
		case n.ch <- respT{
			err:  item.deriveError(),
			idx:  n.idx,
			data: item,
		}:
		default:
			panic("Unexpected blocked response channel on flushBulk")
		}

		n = next
	}

	return nil
}

func (b *Bulker) HasTracer() bool {
	return b.tracer != nil
}

func (b *Bulker) StartTransaction(name, transactionType string) *apm.Transaction {
	return b.tracer.StartTransaction(name, transactionType)
}
