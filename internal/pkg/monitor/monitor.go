// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/es"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultCheckInterval  = 1         // check every second for the new action
	defaultSeqNo          = int64(-1) // the _seq_no in elasticsearch start with 0
	defaultWithExpiration = false
)

const (
	seqNoPrimaryTerm = "seq_no_primary_term"

	fieldSeqNo      = "_seq_no"
	fieldMaxSeqNo   = "max_seq_no"
	fieldExpiration = "expiration"
)

var gCounter uint64

type HitT struct {
	Id     string          `json:"_id"`
	SeqNo  int64           `json:"_seq_no"`
	Index  string          `json:"_index"`
	Source json.RawMessage `json:"_source"`
	Score  *float64        `json:"_score"`
}

type HitsT struct {
	Hits  []HitT `json:"hits"`
	Total struct {
		Relation string `json:"relation"`
		Value    uint64 `json:"value"`
	} `json:"total"`
	MaxScore *float64 `json:"max_score"`
}

type GlobalCheckpointProvider interface {
	GetCheckpoint() int64
}

// Subscription is a subscription to get notified for new documents
type Subscription interface {
	// Output is the channel the monitor send new documents to
	Output() <-chan []es.HitT
}

// Monitor monitors for new documents in an index
type Monitor interface {
	GlobalCheckpointProvider

	// Run runs the monitor
	Run(ctx context.Context) error

	// Subscribe to get notified of documents
	Subscribe() Subscription

	// Unsubscribe from getting notifications on documents
	Unsubscribe(sub Subscription)
}

// Subscription is a subscription to get notified for new documents
type subT struct {
	idx uint64
	c   chan []es.HitT
}

// subT is the channel the monitor send new documents to
func (s *subT) Output() <-chan []es.HitT {
	return s.c
}

// monitorT monitors for new documents in an index
type monitorT struct {
	cli       *elasticsearch.Client
	tmplCheck *dsl.Tmpl
	tmplQuery *dsl.Tmpl

	index          string
	checkInterval  time.Duration
	withExpiration bool

	checkpoint int64 // index global checkpoint

	log zerolog.Logger

	mut  sync.RWMutex
	subs map[uint64]*subT

	readyCh chan error
}

// Option monitor functional option
type Option func(Monitor)

// New creates new monitor
func New(index string, cli *elasticsearch.Client, opts ...Option) (Monitor, error) {
	m := &monitorT{
		index:          index,
		cli:            cli,
		checkInterval:  defaultCheckInterval * time.Second,
		withExpiration: defaultWithExpiration,
		checkpoint:     defaultSeqNo,
		subs:           make(map[uint64]*subT),
	}

	for _, opt := range opts {
		opt(m)
	}

	m.log = log.With().Str("index", m.index).Str("ctx", "index monitor").Logger()

	tmplCheck, err := m.prepareCheckQuery()
	if err != nil {
		return nil, err
	}
	m.tmplCheck = tmplCheck

	tmplQuery, err := m.prepareQuery()
	if err != nil {
		return nil, err
	}
	m.tmplQuery = tmplQuery

	return m, nil
}

// WithCheckInterval sets a periodic check interval
func WithCheckInterval(interval time.Duration) Option {
	return func(m Monitor) {
		m.(*monitorT).checkInterval = interval
	}
}

// WithExpiration sets adds the expiration field to the monitor query
func WithExpiration(withExpiration bool) Option {
	return func(m Monitor) {
		m.(*monitorT).withExpiration = withExpiration
	}
}

// WithReadyChan allows to pass the channel that will signal when monitor is ready
func WithReadyChan(readyCh chan error) Option {
	return func(m Monitor) {
		m.(*monitorT).readyCh = readyCh
	}
}

// Subscribe to get notified of documents
func (m *monitorT) Subscribe() Subscription {
	idx := atomic.AddUint64(&gCounter, 1)

	s := &subT{
		idx: idx,
		c:   make(chan []es.HitT),
	}

	m.mut.Lock()
	m.subs[idx] = s
	m.mut.Unlock()
	return s
}

// Unsubscribe from getting notifications on documents
func (m *monitorT) Unsubscribe(sub Subscription) {
	s, ok := sub.(*subT)
	if !ok {
		return
	}

	m.mut.Lock()
	_, ok = m.subs[s.idx]
	if ok {
		delete(m.subs, s.idx)
	}
	m.mut.Unlock()
}

// GetCheckpoint implements GlobalCheckpointProvider interface
func (m *monitorT) GetCheckpoint() int64 {
	return m.loadCheckpoint()
}

func (m *monitorT) storeCheckpoint(val int64) {
	m.log.Debug().Int64("checkpoint", val).Msg("updated checkpoint")
	atomic.StoreInt64(&m.checkpoint, val)
}

func (m *monitorT) loadCheckpoint() int64 {
	return atomic.LoadInt64(&m.checkpoint)
}

// Run runs monitor.
func (m *monitorT) Run(ctx context.Context) (err error) {
	m.log.Info().Msg("start")
	defer func() {
		m.log.Info().Err(err).Msg("exited")
	}()

	defer func() {
		if m.readyCh != nil {
			m.readyCh <- err
		}
	}()

	// Initialize global checkpoint from the index stats
	var checkpoint int64
	checkpoint, err = queryGlobalCheckpoint(ctx, m.cli, m.index)
	if err != nil {
		m.log.Error().Err(err).Msg("failed to initialize the global checkpoint")
		return err
	}
	m.storeCheckpoint(checkpoint)

	// Signal the monitor is ready
	if m.readyCh != nil {
		m.readyCh <- nil
		m.readyCh = nil
	}

	// Start timer loop to check for global checkpoint changes
	t := time.NewTimer(m.checkInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			hits, err := m.check(ctx)
			if err != nil {
				m.log.Error().Err(err).Msg("failed checking new documents")
			} else {
				m.notify(ctx, hits)
			}
			t.Reset(m.checkInterval)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *monitorT) notify(ctx context.Context, hits []es.HitT) {
	sz := len(hits)
	if sz > 0 {
		maxVal := hits[sz-1].SeqNo
		m.storeCheckpoint(maxVal)

		m.mut.RLock()
		var wg sync.WaitGroup
		wg.Add(len(m.subs))
		for _, s := range m.subs {
			go func(s *subT) {
				defer wg.Done()
				select {
				case s.c <- hits:
				case <-ctx.Done():
				}
			}(s)
		}
		m.mut.RUnlock()
		wg.Wait()
	}
}

func (m *monitorT) check(ctx context.Context) ([]es.HitT, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	checkpoint := m.loadCheckpoint()

	// Run check query that detects that there are new documents available
	params := map[string]interface{}{
		dl.FieldSeqNo: checkpoint,
	}
	if m.withExpiration {
		params[dl.FieldExpiration] = now
	}

	hits, err := m.search(ctx, m.tmplCheck, params)
	if err != nil {
		return nil, err
	}

	if len(hits) == 0 {
		return nil, nil
	}

	// New documents are detected, fetch global checkpoint
	gcp, err := queryGlobalCheckpoint(ctx, m.cli, m.index)
	if err != nil {
		m.log.Error().Err(err).Msg("failed to check the global checkpoint")
		return nil, err
	}

	// If global check point is still not greater that the current known checkpoint, return nothing
	if gcp <= checkpoint {
		return nil, nil
	}

	// Fetch documents capped by the global checkpoint
	// Reusing params for the documents query
	params[dl.FieldMaxSeqNo] = gcp

	hits, err = m.search(ctx, m.tmplQuery, params)
	if err != nil {
		return nil, err
	}

	return hits, nil
}

func (m *monitorT) search(ctx context.Context, tmpl *dsl.Tmpl, params map[string]interface{}) ([]es.HitT, error) {
	query, err := tmpl.Render(params)
	if err != nil {
		return nil, err
	}

	res, err := m.cli.Search(
		m.cli.Search.WithContext(ctx),
		m.cli.Search.WithIndex(m.index),
		m.cli.Search.WithBody(bytes.NewBuffer(query)),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var esres es.Response
	err = json.NewDecoder(res.Body).Decode(&esres)
	if err != nil {
		return nil, err
	}

	if res.IsError() {
		return nil, es.TranslateError(res.StatusCode, esres.Error)
	}

	return esres.Hits.Hits, nil
}

// Prepares minimal query to do the quick check without reading all matches full documents
func (m *monitorT) prepareCheckQuery() (tmpl *dsl.Tmpl, err error) {
	tmpl, root := m.prepareCommon(false)

	root.Source().Includes(dl.FieldSeqNo)
	root.Size(1)

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}
	return
}

// Prepares full documents query
func (m *monitorT) prepareQuery() (tmpl *dsl.Tmpl, err error) {
	tmpl, root := m.prepareCommon(true)
	root.Sort().SortOrder(fieldSeqNo, dsl.SortAscend)

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}
	return
}

func (m *monitorT) prepareCommon(limitMax bool) (*dsl.Tmpl, *dsl.Node) {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	root.Param(seqNoPrimaryTerm, true)

	filter := root.Query().Bool().Filter()
	filter.Range(fieldSeqNo, dsl.WithRangeGT(tmpl.Bind(fieldSeqNo)))
	if limitMax {
		filter.Range(fieldSeqNo, dsl.WithRangeLTE(tmpl.Bind(fieldMaxSeqNo)))
	}
	if m.withExpiration {
		filter.Range(fieldExpiration, dsl.WithRangeGT(tmpl.Bind(fieldExpiration)))
	}

	return tmpl, root
}
