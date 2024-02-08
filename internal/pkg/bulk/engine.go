// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog"
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
	StartTransaction(name, transactionType string) *apm.Transaction
	StartTransactionOptions(name, transactionType string, opts apm.TransactionOptions) *apm.Transaction

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

	CreateAndGetBulker(ctx context.Context, zlog zerolog.Logger, outputName string, outputMap map[string]map[string]interface{}) (Bulk, bool, error)
	GetBulker(outputName string) Bulk
	GetBulkerMap() map[string]Bulk
	CancelFn() context.CancelFunc

	ReadSecrets(ctx context.Context, secretIds []string) (map[string]string, error)
}

const kModBulk = "bulk"

type Bulker struct {
	es                    esapi.Transport
	ch                    chan *bulkT
	opts                  bulkOptT
	blkPool               sync.Pool
	apikeyLimit           *semaphore.Weighted
	tracer                *apm.Tracer
	remoteOutputConfigMap map[string]map[string]interface{}
	bulkerMap             map[string]Bulk
	cancelFn              context.CancelFunc
	remoteOutputMutex     sync.RWMutex
}

const (
	defaultFlushInterval     = time.Second * 5
	defaultFlushThresholdCnt = 32768
	defaultFlushThresholdSz  = 1024 * 1024 * 10
	defaultMaxPending        = 32
	defaultBlockQueueSz      = 32 // Small capacity to allow multiOp to spin fast
	defaultAPIKeyMaxParallel = 32
	defaultApikeyMaxReqSize  = 100 * 1024 * 1024
)

func NewBulker(es esapi.Transport, tracer *apm.Tracer, opts ...BulkOpt) *Bulker {

	bopts := parseBulkOpts(opts...)

	poolFunc := func() interface{} {
		return &bulkT{ch: make(chan respT, 1)}
	}

	return &Bulker{
		opts:                  bopts,
		es:                    es,
		ch:                    make(chan *bulkT, bopts.blockQueueSz),
		blkPool:               sync.Pool{New: poolFunc},
		apikeyLimit:           semaphore.NewWeighted(int64(bopts.apikeyMaxParallel)),
		tracer:                tracer,
		remoteOutputConfigMap: make(map[string]map[string]interface{}),
		// remote ES bulkers
		bulkerMap: make(map[string]Bulk),
	}
}

func (b *Bulker) GetBulker(outputName string) Bulk {
	return b.bulkerMap[outputName]
}

func (b *Bulker) GetBulkerMap() map[string]Bulk {
	return b.bulkerMap
}

func (b *Bulker) CancelFn() context.CancelFunc {
	return b.cancelFn
}

func (b *Bulker) updateBulkerMap(outputName string, newBulker *Bulker) {
	// concurrency control of updating map
	b.remoteOutputMutex.Lock()
	defer b.remoteOutputMutex.Unlock()

	b.bulkerMap[outputName] = newBulker
}

// for remote ES output, create a new bulker in bulkerMap if does not exist
// if bulker exists for output, check if config changed
// if not changed, return the existing bulker
// if changed, stop the existing bulker and create a new one
func (b *Bulker) CreateAndGetBulker(ctx context.Context, zlog zerolog.Logger, outputName string, outputMap map[string]map[string]interface{}) (Bulk, bool, error) {
	hasConfigChanged := b.hasChangedAndUpdateRemoteOutputConfig(zlog, outputName, outputMap[outputName])
	bulker := b.bulkerMap[outputName]
	if bulker != nil && !hasConfigChanged {
		return bulker, false, nil
	}
	if bulker != nil && hasConfigChanged {
		cancelFn := bulker.CancelFn()
		if cancelFn != nil {
			cancelFn()
		}
	}
	bulkCtx, bulkCancel := context.WithCancel(context.Background())
	es, err := b.createRemoteEsClient(bulkCtx, outputName, outputMap)
	if err != nil {
		defer bulkCancel()
		return nil, hasConfigChanged, err
	}
	// starting a new bulker to create/update API keys for remote ES output
	newBulker := NewBulker(es, b.tracer)
	newBulker.cancelFn = bulkCancel

	b.updateBulkerMap(outputName, newBulker)

	errCh := make(chan error)
	go func() {
		runFunc := func() (err error) {
			zlog.Debug().Str("outputName", outputName).Msg("Bulker started")
			return newBulker.Run(bulkCtx)
		}

		errCh <- runFunc()
	}()
	go func() {
		select {
		case err = <-errCh:
			zlog.Error().Err(err).Str("outputName", outputName).Msg("Bulker error")
		case <-bulkCtx.Done():
			zlog.Debug().Str("outputName", outputName).Msg("Bulk context done")
			err = bulkCtx.Err()
		}
	}()

	return newBulker, hasConfigChanged, nil
}

var newESClient = es.NewClient

func (b *Bulker) createRemoteEsClient(ctx context.Context, outputName string, outputMap map[string]map[string]interface{}) (*elasticsearch.Client, error) {
	hostsObj := outputMap[outputName]["hosts"]
	hosts, ok := hostsObj.([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to get hosts from output: %v", hostsObj)
	}
	hostsStrings := make([]string, len(hosts))
	for i, host := range hosts {
		hostsStrings[i], ok = host.(string)
		if !ok {
			return nil, fmt.Errorf("failed to get hosts from output: %v", host)
		}
	}
	serviceToken, ok := outputMap[outputName]["service_token"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get service token from output: %v", outputName)
	}

	cfg := config.Config{
		Output: config.Output{
			Elasticsearch: config.Elasticsearch{
				Hosts:        hostsStrings,
				ServiceToken: serviceToken,
			},
		},
	}
	es, err := newESClient(ctx, &cfg, false, elasticsearchOptions(
		true, b.opts.bi,
	)...)
	if err != nil {
		return nil, err
	}
	return es, nil
}

func elasticsearchOptions(instumented bool, bi build.Info) []es.ConfigOption {
	options := []es.ConfigOption{es.WithUserAgent("Remote-Fleet-Server", bi)}
	if instumented {
		options = append(options, es.InstrumentRoundTripper())
	}
	return options
}

func (b *Bulker) Client() *elasticsearch.Client {
	client, ok := b.es.(*elasticsearch.Client)
	if !ok {
		panic("Client is not an elastic search pointer")
	}
	return client
}

// check if remote output cfg changed
func (b *Bulker) hasChangedAndUpdateRemoteOutputConfig(zlog zerolog.Logger, name string, newCfg map[string]interface{}) bool {
	curCfg := b.remoteOutputConfigMap[name]

	hasChanged := false

	// when output config first added, not reporting change
	if curCfg != nil && !reflect.DeepEqual(curCfg, newCfg) {
		zlog.Info().Str("name", name).Msg("remote output configuration has changed")
		hasChanged = true
	}
	newCfgCopy := make(map[string]interface{})
	for k, v := range newCfg {
		newCfgCopy[k] = v
	}
	b.remoteOutputConfigMap[name] = newCfgCopy
	return hasChanged
}

// read secrets one by one as there is no bulk API yet to read them in one request
func (b *Bulker) ReadSecrets(ctx context.Context, secretIds []string) (map[string]string, error) {
	result := make(map[string]string)
	esClient := b.Client()
	for _, id := range secretIds {
		val, err := ReadSecret(ctx, esClient, id)
		if err != nil {
			return nil, err
		}
		result[id] = val
	}
	return result, nil
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

	zerolog.Ctx(ctx).Info().Interface("opts", &b.opts).Msg("Run bulker with options")

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
				zerolog.Ctx(ctx).Trace().
					Str("mod", kModBulk).
					Int("itemCnt", itemCnt).
					Int("byteCnt", byteCnt).
					Msg("Flush on threshold")

				err = doFlush()

				stopTimer(timer)
			}

		case <-timer.C:
			zerolog.Ctx(ctx).Trace().
				Str("mod", kModBulk).
				Int("itemCnt", itemCnt).
				Int("byteCnt", byteCnt).
				Msg("Flush on timer")
			err = doFlush()

		case <-ctx.Done():
			err = ctx.Err()
		}

	}

	// cancelling context of each remote bulker when Run exits
	defer func() {
		for _, bulker := range b.bulkerMap {
			bulker.CancelFn()()
		}
	}()

	return err
}

func (b *Bulker) flushQueue(ctx context.Context, w *semaphore.Weighted, queue queueT) error {
	start := time.Now()
	zerolog.Ctx(ctx).Trace().
		Str("mod", kModBulk).
		Int("cnt", queue.cnt).
		Int("szPending", queue.pending).
		Str("queue", queue.Type()).
		Msg("flushQueue Wait")

	if err := w.Acquire(ctx, 1); err != nil {
		return err
	}

	zerolog.Ctx(ctx).Trace().
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
			apm.CaptureError(ctx, err).Send()
		}

		zerolog.Ctx(ctx).Trace().
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
	blk.spanLink = opts.spanLink

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
		zerolog.Ctx(ctx).Error().
			Err(ctx.Err()).
			Str("mod", kModBulk).
			Str("action", blk.action.String()).
			Bool("refresh", blk.flags.Has(flagRefresh)).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch abort queue")
		return respT{err: ctx.Err()}
	}

	// Wait for response
	select {
	case resp := <-blk.ch:
		zerolog.Ctx(ctx).Trace().
			Err(resp.err).
			Str("mod", kModBulk).
			Str("action", blk.action.String()).
			Bool("refresh", blk.flags.Has(flagRefresh)).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch OK")

		return resp
	case <-ctx.Done():
		zerolog.Ctx(ctx).Error().
			Err(ctx.Err()).
			Str("mod", kModBulk).
			Str("action", blk.action.String()).
			Bool("refresh", blk.flags.Has(flagRefresh)).
			Dur("rtt", time.Since(start)).
			Msg("Dispatch abort response")
	}

	return respT{err: ctx.Err()}
}
