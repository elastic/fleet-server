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

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
)

type BulkOp struct {
	Id    string
	Index string
	Body  []byte
}

type Bulk interface {
	Create(ctx context.Context, index, id string, body []byte, opts ...Opt) (string, error)
	Index(ctx context.Context, index, id string, body []byte, opts ...Opt) (string, error)
	Update(ctx context.Context, index, id string, body []byte, opts ...Opt) error
	Read(ctx context.Context, index, id string, opts ...Opt) ([]byte, error)
	//	Delete (ctx context.Context, index, id string, opts ...Opt) error

	MUpdate(ctx context.Context, ops []BulkOp, opts ...Opt) error

	Search(ctx context.Context, index []string, body []byte, opts ...Opt) (*es.ResultT, error)

	Client() *elasticsearch.Client
}

type Action string

func (a Action) Str() string { return string(a) }

const (
	ActionCreate Action = "create"
	ActionDelete        = "delete"
	ActionIndex         = "index"
	ActionUpdate        = "update"
	ActionRead          = "read"
	ActionSearch        = "search"
)

const kModBulk = "bulk"

type respT struct {
	idx  int
	err  error
	data interface{}
}

type bulkT struct {
	idx    int
	action Action
	ch     chan respT
	data   []byte
	opts   optionsT
}

type Bulker struct {
	es *elasticsearch.Client
	ch chan bulkT
}

const (
	rPrefix = "{\"docs\": ["
	rSuffix = "]}"

	defaultFlushInterval     = time.Second * 5
	defaultFlushThresholdCnt = 32768
	defaultFlushThresholdSz  = 1024 * 1024 * 10
	defaultMaxPending        = 32
	defaultQueuePrealloc     = 64
)

func InitES(ctx context.Context, cfg *config.Config, opts ...BulkOpt) (*elasticsearch.Client, Bulk, error) {

	es, err := es.NewClient(ctx, cfg, false)
	if err != nil {
		return nil, nil, err
	}

	opts = append(opts,
		WithFlushInterval(cfg.Output.Elasticsearch.BulkFlushInterval),
		WithFlushThresholdCount(cfg.Output.Elasticsearch.BulkFlushThresholdCount),
		WithFlushThresholdSize(cfg.Output.Elasticsearch.BulkFlushThresholdSize),
		WithMaxPending(cfg.Output.Elasticsearch.BulkFlushMaxPending),
	)

	blk := NewBulker(es)
	go func() {
		err := blk.Run(ctx, opts...)
		log.Info().Err(err).Msg("Bulker exit")
	}()

	return es, blk, nil
}

func NewBulker(es *elasticsearch.Client) *Bulker {
	return &Bulker{
		es: es,
		ch: make(chan bulkT),
	}
}

func (b *Bulker) Client() *elasticsearch.Client {
	return b.es
}

func (b *Bulker) parseBulkOpts(opts ...BulkOpt) bulkOptT {
	bopt := bulkOptT{
		flushInterval:     defaultFlushInterval,
		flushThresholdCnt: defaultFlushThresholdCnt,
		flushThresholdSz:  defaultFlushThresholdSz,
		maxPending:        defaultMaxPending,
		queuePrealloc:     defaultQueuePrealloc,
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

type queueT struct {
	action  Action
	queue   []bulkT
	pending int
}

const (
	kQueueBulk = iota
	kQueueRead
	kQueueSearch
	kQueueRefresh
	kNumQueues
)

func (b *Bulker) Run(ctx context.Context, opts ...BulkOpt) error {
	var err error

	bopts := b.parseBulkOpts(opts...)

	// Create timer in stopped state
	timer := time.NewTimer(bopts.flushInterval)
	stopTimer(timer)
	defer timer.Stop()

	w := semaphore.NewWeighted(int64(bopts.maxPending))

	queues := make([]*queueT, 0, kNumQueues)
	for i := 0; i < kNumQueues; i++ {
		var action Action
		switch i {
		case kQueueRead:
			action = ActionRead
		case kQueueSearch:
			action = ActionSearch
		case kQueueBulk, kQueueRefresh:
			// Empty action is correct
		default:
			// Bad programmer
			panic("Unknown bulk queue")
		}

		queues = append(queues, &queueT{
			action: action,
			queue:  make([]bulkT, 0, bopts.queuePrealloc),
		})
	}

	var itemCnt int
	var byteCnt int

	doFlush := func() error {

		for _, q := range queues {
			if q.pending > 0 {
				if err := b.flushQueue(ctx, w, q.queue, q.pending, q.action); err != nil {
					return err
				}

				q.pending = 0
				q.queue = make([]bulkT, 0, bopts.queuePrealloc)
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

		case item := <-b.ch:

			queueIdx := kQueueBulk

			switch item.action {
			case ActionRead:
				queueIdx = kQueueRead
			case ActionSearch:
				queueIdx = kQueueSearch
			default:
				if item.opts.Refresh {
					queueIdx = kQueueRefresh
				}
			}

			q := queues[queueIdx]
			q.queue = append(q.queue, item)
			q.pending += len(item.data)

			// Update threshold counters
			itemCnt += 1
			byteCnt += len(item.data)

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

func (b *Bulker) flushQueue(ctx context.Context, w *semaphore.Weighted, queue []bulkT, szPending int, action Action) error {
	start := time.Now()
	log.Trace().
		Str("mod", kModBulk).
		Int("szPending", szPending).
		Int("sz", len(queue)).
		Str("action", action.Str()).
		Msg("flushQueue Wait")

	if err := w.Acquire(ctx, 1); err != nil {
		return err
	}

	log.Trace().
		Str("mod", kModBulk).
		Dur("tdiff", time.Since(start)).
		Int("szPending", szPending).
		Int("sz", len(queue)).
		Str("action", action.Str()).
		Msg("flushQueue Acquired")

	go func() {
		start := time.Now()

		defer w.Release(1)

		var err error
		switch action {
		case ActionRead:
			err = b.flushRead(ctx, queue, szPending)
		case ActionSearch:
			err = b.flushSearch(ctx, queue, szPending)
		default:
			err = b.flushBulk(ctx, queue, szPending)
		}

		if err != nil {
			failQueue(queue, err)
		}

		log.Trace().
			Err(err).
			Str("mod", kModBulk).
			Int("szPending", szPending).
			Int("sz", len(queue)).
			Str("action", action.Str()).
			Dur("rtt", time.Since(start)).
			Msg("flushQueue Done")

	}()

	return nil
}

func (b *Bulker) flushRead(ctx context.Context, queue []bulkT, szPending int) error {
	start := time.Now()

	buf := bytes.NewBufferString(rPrefix)
	buf.Grow(szPending + len(rSuffix))

	// Each item a JSON array element followed by comma
	for _, item := range queue {
		buf.Write(item.data)
	}

	// Need to strip the last element and append the suffix
	payload := buf.Bytes()
	payload = append(payload[:len(payload)-1], []byte(rSuffix)...)

	// Do actual bulk request; and send response on chan
	req := esapi.MgetRequest{
		Body: bytes.NewReader(payload),
	}
	res, err := req.Do(ctx, b.es)

	if err != nil {
		return err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		return fmt.Errorf("flush: %s", res.String()) // TODO: Wrap error
	}

	var blk MgetResponse
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&blk); err != nil {
		return fmt.Errorf("flush: error parsing response body: %s", err) // TODO: Wrap error
	}

	log.Trace().
		Err(err).
		Str("mod", kModBulk).
		Dur("rtt", time.Since(start)).
		Int("sz", len(blk.Items)).
		Msg("flushRead")

	if len(blk.Items) != len(queue) {
		return fmt.Errorf("Mget queue length mismatch")
	}

	for i, item := range blk.Items {
		citem := item
		queue[i].ch <- respT{
			idx:  queue[i].idx,
			err:  item.deriveError(),
			data: &citem,
		}

	}

	return nil
}

func (b *Bulker) flushSearch(ctx context.Context, queue []bulkT, szPending int) error {
	start := time.Now()

	buf := bytes.Buffer{}
	buf.Grow(szPending)

	for _, item := range queue {
		buf.Write(item.data)
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
		return fmt.Errorf("flush: %s", res.String()) // TODO: Wrap error
	}

	var blk MsearchResponse
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&blk); err != nil {
		return fmt.Errorf("flush: error parsing response body: %s", err) // TODO: Wrap error
	}

	log.Trace().
		Err(err).
		Str("mod", kModBulk).
		Dur("rtt", time.Since(start)).
		Int("took", blk.Took).
		Int("sz", len(blk.Responses)).
		Msg("flushSearch")

	if len(blk.Responses) != len(queue) {
		return fmt.Errorf("Bulk queue length mismatch")
	}

	for i, response := range blk.Responses {

		cResponse := response
		queue[i].ch <- respT{
			idx:  queue[i].idx,
			err:  response.deriveError(),
			data: &cResponse,
		}
	}

	return nil
}

func (b *Bulker) flushBulk(ctx context.Context, queue []bulkT, szPending int) error {

	buf := bytes.Buffer{}
	buf.Grow(szPending)

	doRefresh := "false"
	for _, item := range queue {
		buf.Write(item.data)
		if item.opts.Refresh {
			doRefresh = "true"
		}
	}

	// Do actual bulk request; and send response on chan
	req := esapi.BulkRequest{
		Body:    bytes.NewReader(buf.Bytes()),
		Refresh: doRefresh,
	}
	res, err := req.Do(ctx, b.es)

	if err != nil {
		log.Error().Err(err).Str("mod", kModBulk).Msg("Fail req.Do")
		return err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		log.Error().Str("mod", kModBulk).Str("err", res.String()).Msg("Fail result")
		return fmt.Errorf("flush: %s", res.String()) // TODO: Wrap error
	}

	var blk BulkIndexerResponse
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&blk); err != nil {
		log.Error().Err(err).Str("mod", kModBulk).Msg("Decode error")
		return fmt.Errorf("flush: error parsing response body: %s", err) // TODO: Wrap error
	}

	log.Trace().
		Err(err).
		Bool("refresh", doRefresh == "true").
		Str("mod", kModBulk).
		Int("took", blk.Took).
		Bool("hasErrors", blk.HasErrors).
		Int("sz", len(blk.Items)).
		Msg("flushBulk")

	if len(blk.Items) != len(queue) {
		return fmt.Errorf("Bulk queue length mismatch")
	}

	for i, blkItem := range blk.Items {

		for _, item := range blkItem {

			select {
			case queue[i].ch <- respT{
				idx:  queue[i].idx,
				err:  item.deriveError(),
				data: &item,
			}:
			default:
				panic("Should not happen")
			}

			break
		}
	}

	return nil
}

func failQueue(queue []bulkT, err error) {
	for _, i := range queue {
		i.ch <- respT{
			idx: i.idx,
			err: err,
		}
	}
}

func (b *Bulker) parseOpts(opts ...Opt) optionsT {
	var opt optionsT
	for _, o := range opts {
		o(&opt)
	}
	return opt
}

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

func (b *Bulker) waitBulkAction(ctx context.Context, action Action, index, id string, body []byte, opts ...Opt) (*BulkIndexerResponseItem, error) {
	opt := b.parseOpts(opts...)

	// Serialize request
	var buf bytes.Buffer

	const kSlop = 64
	buf.Grow(len(body) + kSlop)

	if err := b.writeBulkMeta(&buf, action, index, id); err != nil {
		return nil, err
	}

	if err := b.writeBulkBody(&buf, body); err != nil {
		return nil, err
	}

	// Dispatch and wait for response
	resp := b.dispatch(ctx, action, opt, buf.Bytes())
	if resp.err != nil {
		return nil, resp.err
	}

	r := resp.data.(*BulkIndexerResponseItem)
	return r, nil
}

func (b *Bulker) Read(ctx context.Context, index, id string, opts ...Opt) ([]byte, error) {
	opt := b.parseOpts(opts...)

	// Serialize request
	var buf bytes.Buffer

	const kSlop = 64
	buf.Grow(kSlop)

	if err := b.writeMget(&buf, index, id); err != nil {
		return nil, err
	}

	// Process response
	resp := b.dispatch(ctx, ActionRead, opt, buf.Bytes())
	if resp.err != nil {
		return nil, resp.err
	}

	// Interpret response, looking for generated id
	r := resp.data.(*MgetResponseItem)
	return r.Source, nil
}

func (b *Bulker) Search(ctx context.Context, index []string, body []byte, opts ...Opt) (*es.ResultT, error) {
	opt := b.parseOpts(opts...)

	// Serialize request
	var buf bytes.Buffer

	const kSlop = 64
	buf.Grow(len(body) + kSlop)

	if err := b.writeMsearchMeta(&buf, index); err != nil {
		return nil, err
	}

	if err := b.writeMsearchBody(&buf, body); err != nil {
		return nil, err
	}

	// Process response
	resp := b.dispatch(ctx, ActionSearch, opt, buf.Bytes())
	if resp.err != nil {
		return nil, resp.err
	}

	// Interpret response
	r := resp.data.(*MsearchResponseItem)
	return &es.ResultT{HitsT: r.Hits, Aggregations: r.Aggregations}, nil
}

func (b *Bulker) writeMsearchMeta(buf *bytes.Buffer, indices []string) error {
	if err := b.validateIndices(indices); err != nil {
		return err
	}

	switch len(indices) {
	case 0:
		buf.WriteString("{ }\n")
	case 1:
		buf.WriteString(`{"index": "`)
		buf.WriteString(indices[0])
		buf.WriteString("\"}\n")
	default:
		buf.WriteString(`{"index": `)
		if d, err := json.Marshal(indices); err != nil {
			return err
		} else {
			buf.Write(d)
		}
		buf.WriteString("}\n")
	}

	return nil
}

func (b *Bulker) writeMsearchBody(buf *bytes.Buffer, body []byte) error {
	buf.Write(body)
	buf.WriteRune('\n')

	return b.validateBody(body)
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
	// TODO: validate id and index; not quotes anyhow
	return nil
}

// TODO: Fail on non-escaped line feeds
func (b *Bulker) validateBody(body []byte) error {
	if !json.Valid(body) {
		return es.ErrInvalidBody
	}

	return nil
}

func (b *Bulker) writeMget(buf *bytes.Buffer, index, id string) error {
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

func (b *Bulker) writeBulkMeta(buf *bytes.Buffer, action Action, index, id string) error {
	if err := b.validateMeta(index, id); err != nil {
		return err
	}

	buf.WriteString(`{"`)
	buf.WriteString(action.Str())
	buf.WriteString(`":{`)
	if id != "" {
		buf.WriteString(`"_id":"`)
		buf.WriteString(id)
		buf.WriteString(`",`)
	}

	buf.WriteString(`"_index":"`)
	buf.WriteString(index)
	buf.WriteString("\"}}\n")
	return nil
}

func (b *Bulker) writeBulkBody(buf *bytes.Buffer, body []byte) error {
	if body == nil {
		return nil
	}

	buf.Write(body)
	buf.WriteRune('\n')

	return b.validateBody(body)
}

func (b *Bulker) dispatch(ctx context.Context, action Action, opts optionsT, data []byte) respT {
	start := time.Now()

	ch := make(chan respT, 1)

	item := bulkT{
		0,
		action,
		ch,
		data,
		opts,
	}

	// Dispatch to bulk Run loop
	select {
	case b.ch <- item:
	case <-ctx.Done():
		log.Error().
			Err(ctx.Err()).
			Str("mod", kModBulk).
			Str("action", action.Str()).
			Bool("refresh", opts.Refresh).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch abort queue")
		return respT{err: ctx.Err()}
	}

	// Wait for response
	select {
	case resp := <-ch:
		log.Trace().
			Str("mod", kModBulk).
			Str("action", action.Str()).
			Bool("refresh", opts.Refresh).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch OK")

		return resp
	case <-ctx.Done():
		log.Error().
			Err(ctx.Err()).
			Str("mod", kModBulk).
			Str("action", action.Str()).
			Bool("refresh", opts.Refresh).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch abort response")
	}

	return respT{err: ctx.Err()}
}
