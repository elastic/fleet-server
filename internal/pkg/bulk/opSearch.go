// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/mailru/easyjson"
	"github.com/rs/zerolog/log"
)

func (b *Bulker) Search(ctx context.Context, index string, body []byte, opts ...Opt) (*es.ResultT, error) {
	var opt optionsT
	if len(opts) > 0 {
		opt = b.parseOpts(opts...)
	}

	blk := b.newBlk(ActionSearch, opt)

	// Serialize request
	const kSlop = 64
	blk.buf.Grow(len(body) + kSlop)

	if err := b.writeMsearchMeta(&blk.buf, index, opt.Indices); err != nil {
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

	// Interpret response
	r := resp.data.(*MsearchResponseItem)
	return &es.ResultT{HitsT: r.Hits, Aggregations: r.Aggregations}, nil
}

func (b *Bulker) writeMsearchMeta(buf *Buf, index string, moreIndices []string) error {
	if err := b.validateIndex(index); err != nil {
		return err
	}

	if len(moreIndices) > 0 {
		if err := b.validateIndices(moreIndices); err != nil {
			return err
		}

		indices := []string{index}
		indices = append(indices, moreIndices...)

		buf.WriteString(`{"index": `)
		if d, err := json.Marshal(indices); err != nil {
			return err
		} else {
			buf.Write(d)
		}
		buf.WriteString("}\n")
	} else if len(index) == 0 {
		buf.WriteString("{ }\n")
	} else {
		buf.WriteString(`{"index": "`)
		buf.WriteString(index)
		buf.WriteString("\"}\n")
	}

	return nil
}

func (b *Bulker) writeMsearchBody(buf *Buf, body []byte) error {
	buf.Write(body)
	buf.WriteRune('\n')

	return b.validateBody(body)
}

func (b *Bulker) flushSearch(ctx context.Context, queue queueT) error {
	start := time.Now()

	const kRoughEstimatePerItem = 256

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

	// Do actual bulk request; and send response on chan
	req := esapi.MsearchRequest{
		Body: bytes.NewReader(buf.Bytes()),
	}
	res, err := req.Do(ctx, b.es)

	if err != nil {
		return err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		log.Error().Err(err).Str("mod", kModBulk).Msg("Fail writeMsearchBody")
		return parseError(res)
	}

	// Reuse buffer
	buf.Reset()

	bodySz, err := buf.ReadFrom(res.Body)
	if err != nil {
		log.Error().Err(err).Str("mod", kModBulk).Msg("MsearchResponse error")
		return err
	}

	// prealloc slice
	var blk MsearchResponse
	blk.Responses = make([]MsearchResponseItem, 0, queueCnt)

	if err = easyjson.Unmarshal(buf.Bytes(), &blk); err != nil {
		log.Error().Err(err).Str("mod", kModBulk).Msg("Unmarshal error")
		return err
	}

	log.Trace().
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
