// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog/log"
	"go.elastic.co/apm/v2"
	"golang.org/x/sync/semaphore"
)

type APIKey = apikey.APIKey
type SecurityInfo = apikey.SecurityInfo
type APIKeyMetadata = apikey.APIKeyMetadata

var (
	ErrNoQuotes = errors.New("quoted literal not supported")
)

type MultiOp struct {
	ID    string
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
	HasTracer() bool

	// Multi Operation API's run in the bulk engine
	MCreate(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error)
	MIndex(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error)
	MUpdate(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error)
	MDelete(ctx context.Context, ops []MultiOp, opts ...Opt) ([]BulkIndexerResponseItem, error)

	// APIKey operations
	APIKeyCreate(ctx context.Context, name, ttl string, roles []byte, meta interface{}) (*APIKey, error)
	APIKeyRead(ctx context.Context, id string, withOwner bool) (*APIKeyMetadata, error)
	APIKeyAuth(ctx context.Context, key APIKey) (*SecurityInfo, error)
	APIKeyInvalidate(ctx context.Context, ids ...string) error
	APIKeyUpdate(ctx context.Context, id, outputPolicyHash string, roles []byte) error

	// Accessor used to talk to elastic search direcly bypassing bulk engine
	Client() *elasticsearch.Client
}

const kModBulk = "bulk"

type Bulker struct {
	es          esapi.Transport
	ch          chan *bulkT
	opts        bulkOptT
	blkPool     sync.Pool
	apikeyLimit *semaphore.Weighted
	tracer      *apm.Tracer
}

const (
	defaultFlushInterval     = time.Second * 5
	defaultFlushThresholdCnt = 32768
	defaultFlushThresholdSz  = 1024 * 1024 * 10
	defaultMaxPending        = 32
	defaultBlockQueueSz      = 32 // Small capacity to allow multiOp to spin fast
	defaultAPIKeyMaxParallel = 32
	defaultApikeyMaxReqSize  = 100 * 1024 * 1024
	defaultRefreshParam      = "true"
)

func NewBulker(es esapi.Transport, tracer *apm.Tracer, opts ...BulkOpt) *Bulker {

	bopts := parseBulkOpts(opts...)

	poolFunc := func() interface{} {
		return &bulkT{ch: make(chan respT, 1)}
	}

	return &Bulker{
		opts:        bopts,
		es:          es,
		ch:          make(chan *bulkT, bopts.blockQueueSz),
		blkPool:     sync.Pool{New: poolFunc},
		apikeyLimit: semaphore.NewWeighted(int64(bopts.apikeyMaxParallel)),
		tracer:      tracer,
	}
}

func (b *Bulker) Client() *elasticsearch.Client {
	client, ok := b.es.(*elasticsearch.Client)
	if !ok {
		panic("Client is not an elastic search pointer")
	}
	return client
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
	case ActionFleetSearch:
		queueIdx = kQueueFleetSearch
	case ActionRead:
		if forceRefresh {
			queueIdx = kQueueRefreshRead
		} else {
			queueIdx = kQueueRead
		}
	case ActionUpdateAPIKey:
		queueIdx = kQueueAPIKeyUpdate
	default:
		if forceRefresh {
			queueIdx = kQueueRefreshBulk
		}
	}

	return queueIdx
}

func (b *Bulker) Run(ctx context.Context) error {
	var err error

	log.Info().Interface("opts", &b.opts).Msg("Run bulker with options")

	// Create timer in stopped state
	timer := time.NewTimer(b.opts.flushInterval)
	stopTimer(timer)
	defer timer.Stop()

	w := semaphore.NewWeighted(int64(b.opts.maxPending))

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

		return nil
	}

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
				timer.Reset(b.opts.flushInterval)
			}

			// Threshold test, short circuit timer on pending count
			if itemCnt >= b.opts.flushThresholdCnt || byteCnt >= b.opts.flushThresholdSz {
				log.Trace().
					Str("mod", kModBulk).
					Int("itemCnt", itemCnt).
					Int("byteCnt", byteCnt).
					Msg("Flush on threshold")

				err = doFlush()

				stopTimer(timer)
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

		if b.tracer != nil {
			trans := b.tracer.StartTransaction(fmt.Sprintf("Flush queue %s", queue.Type()), "bulker")
			trans.Context.SetLabel("queue.size", queue.cnt)
			trans.Context.SetLabel("queue.pending", queue.pending)
			ctx = apm.ContextWithTransaction(ctx, trans)
			defer trans.End()
		}

		defer w.Release(1)

		var err error
		switch queue.ty {
		case kQueueRead, kQueueRefreshRead:
			err = b.flushRead(ctx, queue)
		case kQueueSearch, kQueueFleetSearch:
			err = b.flushSearch(ctx, queue)
		case kQueueAPIKeyUpdate:
			err = b.flushUpdateAPIKey(ctx, queue)
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
	blk := b.blkPool.Get().(*bulkT) //nolint:errcheck // we control what is placed in the pool
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
			Str("action", blk.action.String()).
			Bool("refresh", blk.flags.Has(flagRefresh)). // TODO change refresh to string and fix mapping
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
			Str("action", blk.action.String()).
			Bool("refresh", blk.flags.Has(flagRefresh)). // TODO change refresh to string and fix mapping
			Dur("rtt", time.Since(start)).
			Msg("Dispatch OK")

		return resp
	case <-ctx.Done():
		log.Error().
			Err(ctx.Err()).
			Str("mod", kModBulk).
			Str("action", blk.action.String()).
			Bool("refresh", blk.flags.Has(flagRefresh)). // TODO change refresh to string and fix mapping
			Dur("rtt", time.Since(start)).
			Msg("Dispatch abort response")
	}

	return respT{err: ctx.Err()}
}
