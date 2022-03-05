// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/mailru/easyjson"
	"github.com/rs/zerolog/log"
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
	var opt optionsT
	if len(opts) > 0 {
		opt = b.parseOpts(opts...)
	}

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

	// Dispatch and wait for response
	resp := b.dispatch(ctx, blk)
	if resp.err != nil {
		return nil, resp.err
	}
	b.freeBlk(blk)

	r := resp.data.(*BulkIndexerResponseItem)
	return r, nil
}

func (b *Bulker) writeMget(buf *Buf, index, id string) error {
	if err := b.validateMeta(index, id); err != nil {
		return err
	}

	buf.WriteString(`{"_index":"`)
	buf.WriteString(index)
	buf.WriteString(`","_id":"`)
	buf.WriteString(id)
	buf.WriteString(`"},`)
	return nil
}

func (b *Bulker) writeBulkMeta(buf *Buf, action, index, id, retry string) error {
	if err := b.validateMeta(index, id); err != nil {
		return err
	}

	buf.WriteString(`{"`)
	buf.WriteString(action)
	buf.WriteString(`":{`)
	if id != "" {
		buf.WriteString(`"_id":"`)
		buf.WriteString(id)
		buf.WriteString(`",`)
	}
	if retry != "" {
		buf.WriteString(`"retry_on_conflict":`)
		buf.WriteString(retry)
		buf.WriteString(`,`)
	}

	buf.WriteString(`"_index":"`)
	buf.WriteString(index)
	buf.WriteString("\"}}\n")

	return nil
}

func (b *Bulker) writeBulkBody(buf *Buf, action actionT, body []byte) error {
	if len(body) == 0 {
		if action == ActionDelete {
			return nil
		}

		// Weird to index, create, or update empty, but will allow
		buf.WriteString("{}\n")
		return nil
	}

	if err := b.validateBody(body); err != nil {
		return err
	}

	buf.Write(body)
	buf.WriteRune('\n')
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
		const kIdFraming = 9
		idSz = kIdFraming + len(id)
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
	for n := queue.head; n != nil; n = n.next {
		buf.Write(n.buf.Bytes())
		queueCnt += 1
	}

	// Do actual bulk request; defer to the client
	req := esapi.BulkRequest{
		Body: bytes.NewReader(buf.Bytes()),
	}

	if queue.ty == kQueueRefreshBulk {
		req.Refresh = "true"
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

	if err = easyjson.Unmarshal(buf.Bytes(), &blk); err != nil {
		log.Error().
			Err(err).
			Str("mod", kModBulk).
			Msg("Unmarshal error")
		return err
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
