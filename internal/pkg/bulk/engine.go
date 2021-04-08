// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
)

var (
	ErrNoQuotes = errors.New("Quoted literal not supported")
)

type MultiOp struct {
	Id    string
	Index string
	Body  []byte
}

type Bulk interface {

	// Synchronous operations run in the bulk engine
	Create(ctx context.Context, index, id string, body []byte, opts ...Opt) (string, error)
	Read(ctx context.Context, index, id string, opts ...Opt) ([]byte, error)
	Update(ctx context.Context, index, id string, body []byte, opts ...Opt) error
	Delete(ctx context.Context, index, id string, opts ...Opt) error
	Index(ctx context.Context, index, id string, body []byte, opts ...Opt) (string, error)
	Search(ctx context.Context, index string, body []byte, opts ...Opt) (*es.ResultT, error)

	// Multi Operation API's run in the bulk engine
	MCreate(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error)
	MIndex(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error)
	MUpdate(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error)
	MDelete(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error)

	// Accessor used to talk to elastic search direcly bypassing bulk engine
	Client() *elasticsearch.Client
}

const kModBulk = "bulk"

type Bulker struct {
	es esapi.Transport
	ch chan *bulkT

	blkPool sync.Pool
}

const (
	defaultFlushInterval     = time.Second * 5
	defaultFlushThresholdCnt = 32768
	defaultFlushThresholdSz  = 1024 * 1024 * 10
	defaultMaxPending        = 32
	defaultBlockQueueSz      = 32 // Small capacity to allow multiOp to spin fast
)

func InitES(ctx context.Context, cfg *config.Config, opts ...BulkOpt) (*elasticsearch.Client, Bulk, error) {

	es, err := es.NewClient(ctx, cfg, false)
	if err != nil {
		return nil, nil, err
	}

	// Options specified on API should override config
	nopts := []BulkOpt{
		WithFlushInterval(cfg.Output.Elasticsearch.BulkFlushInterval),
		WithFlushThresholdCount(cfg.Output.Elasticsearch.BulkFlushThresholdCount),
		WithFlushThresholdSize(cfg.Output.Elasticsearch.BulkFlushThresholdSize),
		WithMaxPending(cfg.Output.Elasticsearch.BulkFlushMaxPending),
	}
	nopts = append(nopts, opts...)

	blk := NewBulker(es)
	go func() {
		err := blk.Run(ctx, nopts...)
		log.Info().Err(err).Msg("Bulker exit")
	}()

	return es, blk, nil
}

func NewBulker(es esapi.Transport) *Bulker {

	poolFunc := func() interface{} {
		return &bulkT{ch: make(chan respT, 1)}
	}

	return &Bulker{
		es:      es,
		ch:      make(chan *bulkT, defaultBlockQueueSz),
		blkPool: sync.Pool{New: poolFunc},
	}
}

func (b *Bulker) Client() *elasticsearch.Client {
	client, ok := b.es.(*elasticsearch.Client)
	if !ok {
		panic("Client is not an elastic search pointer")
	}
	return client
}

func (b *Bulker) parseBulkOpts(opts ...BulkOpt) bulkOptT {
	bopt := bulkOptT{
		flushInterval:     defaultFlushInterval,
		flushThresholdCnt: defaultFlushThresholdCnt,
		flushThresholdSz:  defaultFlushThresholdSz,
		maxPending:        defaultMaxPending,
	}

	for _, f := range opts {
		f(&bopt)
	}

	return bopt
}

// Stop timer, but don't stall on channel.
// API doesn't not seem to work as specified.
func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func blkToQueueType(blk *bulkT) queueType {
	queueIdx := kQueueBulk

	forceRefresh := blk.flags.Has(flagRefresh)

	switch blk.action {
	case ActionSearch:
		queueIdx = kQueueSearch
	case ActionRead:
		if forceRefresh {
			queueIdx = kQueueRefreshRead
		} else {
			queueIdx = kQueueRead
		}
	default:
		if forceRefresh {
			queueIdx = kQueueRefreshBulk
		}
	}

	return queueIdx
}

func (b *Bulker) Run(ctx context.Context, opts ...BulkOpt) error {
	var err error

	bopts := b.parseBulkOpts(opts...)

	log.Info().Interface("opts", &bopts).Msg("Run bulker with options")

	// Create timer in stopped state
	timer := time.NewTimer(bopts.flushInterval)
	stopTimer(timer)
	defer timer.Stop()

	w := semaphore.NewWeighted(int64(bopts.maxPending))

	var queues [kNumQueues]queueT

	var i queueType
	for ; i < kNumQueues; i++ {
		queues[i].ty = i
	}

	var itemCnt int
	var byteCnt int

	doFlush := func() error {

		for i := range queues {
			q := &queues[i]
			if q.pending > 0 {

				// Pass queue structure by value
				if err := b.flushQueue(ctx, w, *q); err != nil {
					return err
				}

				// Reset local queue stored in array
				q.cnt = 0
				q.head = nil
				q.pending = 0
			}
		}

		// Reset threshold counters
		itemCnt = 0
		byteCnt = 0

		stopTimer(timer)
		return nil
	}

LOOP:
	for err == nil {

		select {

		case blk := <-b.ch:

			queueIdx := blkToQueueType(blk)
			q := &queues[queueIdx]

			// Prepend block to head of target queue
			blk.next = q.head
			q.head = blk

			// Update pending count on target queue
			q.cnt += 1
			q.pending += blk.buf.Len()

			// Update threshold counters
			itemCnt += 1
			byteCnt += blk.buf.Len()

			// Start timer on first queued item
			if itemCnt == 1 {
				timer.Reset(bopts.flushInterval)
			}

			// Threshold test, short circuit timer on pending count
			if itemCnt >= bopts.flushThresholdCnt || byteCnt >= bopts.flushThresholdSz {
				log.Trace().
					Str("mod", kModBulk).
					Int("itemCnt", itemCnt).
					Int("byteCnt", byteCnt).
					Msg("Flush on threshold")

				err = doFlush()
			}

		case <-timer.C:
			log.Trace().
				Str("mod", kModBulk).
				Int("itemCnt", itemCnt).
				Int("byteCnt", byteCnt).
				Msg("Flush on timer")
			err = doFlush()

		case <-ctx.Done():
			err = ctx.Err()
			break LOOP

		}

	}

	return err
}

func (b *Bulker) flushQueue(ctx context.Context, w *semaphore.Weighted, queue queueT) error {
	start := time.Now()
	log.Trace().
		Str("mod", kModBulk).
		Int("cnt", queue.cnt).
		Int("szPending", queue.pending).
		Str("queue", queue.Type()).
		Msg("flushQueue Wait")

	if err := w.Acquire(ctx, 1); err != nil {
		return err
	}

	log.Trace().
		Str("mod", kModBulk).
		Int("cnt", queue.cnt).
		Dur("tdiff", time.Since(start)).
		Int("szPending", queue.pending).
		Str("queue", queue.Type()).
		Msg("flushQueue Acquired")

	go func() {
		start := time.Now()

		defer w.Release(1)

		var err error
		switch queue.ty {
		case kQueueRead, kQueueRefreshRead:
			err = b.flushRead(ctx, queue)
		case kQueueSearch:
			err = b.flushSearch(ctx, queue)
		default:
			err = b.flushBulk(ctx, queue)
		}

		if err != nil {
			failQueue(queue, err)
		}

		log.Trace().
			Err(err).
			Str("mod", kModBulk).
			Int("cnt", queue.cnt).
			Int("szPending", queue.pending).
			Str("queue", queue.Type()).
			Dur("rtt", time.Since(start)).
			Msg("flushQueue Done")

	}()

	return nil
}

func failQueue(queue queueT, err error) {
	for n := queue.head; n != nil; {
		next := n.next // 'n' is invalid immediately on channel send
		n.ch <- respT{
			err: err,
		}
		n = next
	}
}

func (b *Bulker) parseOpts(opts ...Opt) optionsT {
	var opt optionsT
	for _, o := range opts {
		o(&opt)
	}
	return opt
}

func (b *Bulker) newBlk(action actionT, opts optionsT) *bulkT {
	blk := b.blkPool.Get().(*bulkT)
	blk.action = action
	if opts.Refresh {
		blk.flags.Set(flagRefresh)
	}
	return blk
}

func (b *Bulker) freeBlk(blk *bulkT) {
	blk.reset()
	b.blkPool.Put(blk)
}

func (b *Bulker) validateIndex(index string) error {
	// TODO: index
	return nil
}

func (b *Bulker) validateIndices(indices []string) error {
	for _, i := range indices {
		if err := b.validateIndex(i); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bulker) validateMeta(index, id string) error {

	// Quotes on id are legal, but weird.  Disallow for now.
	if strings.IndexByte(index, '"') != -1 || strings.IndexByte(id, '"') != -1 {
		return ErrNoQuotes
	}
	return nil
}

// TODO: Fail on non-escaped line feeds
func (b *Bulker) validateBody(body []byte) error {
	if !json.Valid(body) {
		return es.ErrInvalidBody
	}

	return nil
}

func (b *Bulker) dispatch(ctx context.Context, blk *bulkT) respT {
	start := time.Now()

	// Dispatch to bulk Run loop
	select {
	case b.ch <- blk:
	case <-ctx.Done():
		log.Error().
			Err(ctx.Err()).
			Str("mod", kModBulk).
			Str("action", blk.action.Str()).
			Bool("refresh", blk.flags.Has(flagRefresh)).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch abort queue")
		return respT{err: ctx.Err()}
	}

	// Wait for response
	select {
	case resp := <-blk.ch:
		log.Trace().
			Err(resp.err).
			Str("mod", kModBulk).
			Str("action", blk.action.Str()).
			Bool("refresh", blk.flags.Has(flagRefresh)).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch OK")

		return resp
	case <-ctx.Done():
		log.Error().
			Err(ctx.Err()).
			Str("mod", kModBulk).
			Str("action", blk.action.Str()).
			Bool("refresh", blk.flags.Has(flagRefresh)).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch abort response")
	}

	return respT{err: ctx.Err()}
}
