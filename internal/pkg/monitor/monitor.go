// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultCheckInterval  = 1 * time.Second // check every second for the new action
	defaultSeqNo          = int64(-1)       // the _seq_no in elasticsearch start with 0
	defaultWithExpiration = false

	// Making the default fetch size larger, in order to increase the throughput of the monitor.
	// This is configurable as well, so can be adjusted based on the memory size of the container if needed.
	// Seems like the usage of smaller actions, one or few agents in the action document would be more prevalent in the future.
	// For example, as of now the current size of osquery action JSON document for 1000 agents is 40KB.
	// Assuiming the worst case scenario of 1000 of document fetched, we are looking at 50MB slice.
	// One action can be split up into multiple documents up to the 1000 agents per action if needed.
	defaultFetchSize = 1000

	tightLoopCheckInterval = 10 * time.Millisecond // when we get a full page (fetchSize) of documents, use this interval to repeatedly poll for more records
)

const (
	seqNoPrimaryTerm = "seq_no_primary_term"

	fieldSeqNo      = "_seq_no"
	fieldMaxSeqNo   = "max_seq_no"
	fieldExpiration = "expiration"
)

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

// SimpleMonitor monitors for new documents in an index
type BaseMonitor interface {
	GlobalCheckpointProvider

	// Run runs the monitor
	Run(ctx context.Context) error
}

// SimpleMonitor monitors for new documents in an index
type SimpleMonitor interface {
	BaseMonitor
	// Output is the channel the monitor send new documents to
	Output() <-chan []es.HitT
}

// simpleMonitorT monitors for new documents in an index
type simpleMonitorT struct {
	cli       *elasticsearch.Client
	tmplCheck *dsl.Tmpl
	tmplQuery *dsl.Tmpl

	index          string
	checkInterval  time.Duration
	withExpiration bool
	fetchSize      int

	checkpoint int64 // index global checkpoint

	log zerolog.Logger

	outCh chan []es.HitT

	readyCh chan error
}

// Option monitor functional option
type Option func(SimpleMonitor)

// New creates new simple monitor
func NewSimple(index string, cli *elasticsearch.Client, opts ...Option) (SimpleMonitor, error) {
	m := &simpleMonitorT{
		index:          index,
		cli:            cli,
		checkInterval:  defaultCheckInterval,
		withExpiration: defaultWithExpiration,
		fetchSize:      defaultFetchSize,
		checkpoint:     defaultSeqNo,
		outCh:          make(chan []es.HitT, 1),
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
func WithFetchSize(fetchSize int) Option {
	return func(m SimpleMonitor) {
		if fetchSize > 0 {
			m.(*simpleMonitorT).fetchSize = fetchSize
		}
	}
}

// WithCheckInterval sets a periodic check interval
func WithCheckInterval(interval time.Duration) Option {
	return func(m SimpleMonitor) {
		m.(*simpleMonitorT).checkInterval = interval
	}
}

// WithExpiration sets adds the expiration field to the monitor query
func WithExpiration(withExpiration bool) Option {
	return func(m SimpleMonitor) {
		m.(*simpleMonitorT).withExpiration = withExpiration
	}
}

// WithReadyChan allows to pass the channel that will signal when monitor is ready
func WithReadyChan(readyCh chan error) Option {
	return func(m SimpleMonitor) {
		m.(*simpleMonitorT).readyCh = readyCh
	}
}

// Output output channel for the monitor
func (m *simpleMonitorT) Output() <-chan []es.HitT {
	return m.outCh
}

// GetCheckpoint implements GlobalCheckpointProvider interface
func (m *simpleMonitorT) GetCheckpoint() int64 {
	return m.loadCheckpoint()
}

func (m *simpleMonitorT) storeCheckpoint(val int64) {
	m.log.Debug().Int64("checkpoint", val).Msg("updated checkpoint")
	atomic.StoreInt64(&m.checkpoint, val)
}

func (m *simpleMonitorT) loadCheckpoint() int64 {
	return atomic.LoadInt64(&m.checkpoint)
}

// Run runs monitor.
func (m *simpleMonitorT) Run(ctx context.Context) (err error) {
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
			interval := m.checkInterval

			hits, err := m.check(ctx)
			if err != nil {
				m.log.Error().Err(err).Msg("failed checking new documents")
			} else {
				count := m.notify(ctx, hits)

				// Change check interval if fetched the full page (m.fetchSize) of documents
				if count == m.fetchSize {
					m.log.Debug().Int("count", count).Dur("wait_next_check", interval).Msg("tight loop check")
					interval = tightLoopCheckInterval
				}
			}
			t.Reset(interval)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *simpleMonitorT) notify(ctx context.Context, hits []es.HitT) int {
	sz := len(hits)
	if sz > 0 {
		select {
		case m.outCh <- hits:
			maxVal := hits[sz-1].SeqNo
			m.storeCheckpoint(maxVal)
			return sz
		case <-ctx.Done():
		}
	}
	return 0
}

func (m *simpleMonitorT) check(ctx context.Context) ([]es.HitT, error) {
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

func (m *simpleMonitorT) search(ctx context.Context, tmpl *dsl.Tmpl, params map[string]interface{}) ([]es.HitT, error) {
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
		err = es.TranslateError(res.StatusCode, esres.Error)
	}

	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			m.log.Debug().Str("index", m.index).Msg(es.ErrIndexNotFound.Error())
			return nil, nil
		}
		return nil, err
	}

	return esres.Hits.Hits, nil
}

// Prepares minimal query to do the quick check without reading all matches full documents
func (m *simpleMonitorT) prepareCheckQuery() (tmpl *dsl.Tmpl, err error) {
	tmpl, root := m.prepareCommon(false)

	root.Source().Includes(dl.FieldSeqNo)
	root.Size(1)

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}
	return
}

// Prepares full documents query
func (m *simpleMonitorT) prepareQuery() (tmpl *dsl.Tmpl, err error) {
	tmpl, root := m.prepareCommon(true)
	root.Size(uint64(m.fetchSize))
	root.Sort().SortOrder(fieldSeqNo, dsl.SortAscend)

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}
	return
}

func (m *simpleMonitorT) prepareCommon(limitMax bool) (*dsl.Tmpl, *dsl.Node) {
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
