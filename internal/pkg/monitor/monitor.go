// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultPollTimeout    = 4 * time.Minute // default long poll timeout
	defaultSeqNo          = int64(-1)       // the _seq_no in elasticsearch start with 0
	defaultWithExpiration = false

	// Making the default fetch size larger, in order to increase the throughput of the monitor.
	// This is configurable as well, so can be adjusted based on the memory size of the container if needed.
	// Seems like the usage of smaller actions, one or few agents in the action document would be more prevalent in the future.
	// For example, as of now the current size of osquery action JSON document for 1000 agents is 40KB.
	// Assuiming the worst case scenario of 1000 of document fetched, we are looking at 50MB slice.
	// One action can be split up into multiple documents up to the 1000 agents per action if needed.
	defaultFetchSize = 1000

	// Retry delay on error waiting on the global checkpoint update.
	// This is the wait time between requests to elastisearch in case if:
	// 1. Index is not found (index is created only on the first document save)
	// 2. Any other error waiting on global checkpoint, except timeouts.
	// For the long poll timeout, start a new request as soon as possible.
	retryDelay = 3 * time.Second
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
	GetCheckpoint() sqn.SeqNo
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
	esCli     *elasticsearch.Client
	monCli    *elasticsearch.Client
	tmplCheck *dsl.Tmpl
	tmplQuery *dsl.Tmpl

	index          string
	pollTimeout    time.Duration
	withExpiration bool
	fetchSize      int

	checkpoint sqn.SeqNo    // index global checkpoint
	mx         sync.RWMutex // checkpoint mutex

	log zerolog.Logger

	outCh chan []es.HitT

	readyCh chan error
}

// Option monitor functional option
type Option func(SimpleMonitor)

// New creates new simple monitor
func NewSimple(index string, esCli, monCli *elasticsearch.Client, opts ...Option) (SimpleMonitor, error) {

	m := &simpleMonitorT{
		index:          index,
		esCli:          esCli,
		monCli:         monCli,
		pollTimeout:    defaultPollTimeout,
		withExpiration: defaultWithExpiration,
		fetchSize:      defaultFetchSize,
		checkpoint:     sqn.DefaultSeqNo,
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

// WithPollTimeout sets the global checkpoint polling timeout
func WithPollTimeout(to time.Duration) Option {
	return func(m SimpleMonitor) {
		m.(*simpleMonitorT).pollTimeout = to
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
func (m *simpleMonitorT) GetCheckpoint() sqn.SeqNo {
	return m.loadCheckpoint()
}

func (m *simpleMonitorT) storeCheckpoint(val sqn.SeqNo) {
	m.log.Debug().Ints64("checkpoints", val).Msg("updated checkpoint")
	m.mx.Lock()
	defer m.mx.Unlock()
	m.checkpoint = val.Clone()
}

func (m *simpleMonitorT) loadCheckpoint() sqn.SeqNo {
	m.mx.RLock()
	defer m.mx.RUnlock()
	return m.checkpoint.Clone()
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
	var checkpoint sqn.SeqNo
	checkpoint, err = queryGlobalCheckpoint(ctx, m.monCli, m.index)
	if err != nil {
		m.log.Error().Err(err).Msg("failed to initialize the global checkpoints")
		return err
	}
	m.storeCheckpoint(checkpoint)

	// Signal the monitor is ready
	if m.readyCh != nil {
		m.readyCh <- nil
		m.readyCh = nil
	}

	for {
		checkpoint := m.loadCheckpoint()

		// Wait checkpoint advance
		newCheckpoint, err := waitCheckpointAdvance(ctx, m.monCli, m.index, checkpoint, m.pollTimeout)
		if err != nil {
			if errors.Is(err, es.ErrIndexNotFound) {
				// Wait until created
				m.log.Debug().Msgf("index not found, poll again in %v", retryDelay)
			} else if errors.Is(err, es.ErrTimeout) {
				// Timed out, wait again
				m.log.Debug().Msg("timeout on global checkpoints advance, poll again")
				continue
			} else {
				// Log the error and keep trying
				m.log.Info().Err(err).Msg("failed on waiting for global checkpoints advance")
			}

			// Delay next attempt
			err = sleep.WithContext(ctx, retryDelay)
			if err != nil {
				return err
			}
		}

		// Fetch up to known checkpoint
		count := m.fetchSize
		for count == m.fetchSize {
			hits, err := m.fetch(ctx, newCheckpoint)
			if err != nil {
				m.log.Error().Err(err).Msg("failed checking new documents")
				break
			}
			count = m.notify(ctx, hits)
		}
	}
}

func (m *simpleMonitorT) notify(ctx context.Context, hits []es.HitT) int {
	sz := len(hits)
	if sz > 0 {
		select {
		case m.outCh <- hits:
			maxVal := hits[sz-1].SeqNo
			m.storeCheckpoint([]int64{maxVal})
			return sz
		case <-ctx.Done():
		}
	}
	return 0
}

func (m *simpleMonitorT) fetch(ctx context.Context, maxCheckpoint sqn.SeqNo) ([]es.HitT, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	checkpoint := m.loadCheckpoint()

	// Run check query that detects that there are new documents available
	params := map[string]interface{}{
		dl.FieldSeqNo:    checkpoint.Value(),
		dl.FieldMaxSeqNo: maxCheckpoint.Value(),
	}
	if m.withExpiration {
		params[dl.FieldExpiration] = now
	}

	hits, err := m.search(ctx, m.tmplQuery, params)
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

	res, err := m.esCli.Search(
		m.esCli.Search.WithContext(ctx),
		m.esCli.Search.WithIndex(m.index),
		m.esCli.Search.WithBody(bytes.NewBuffer(query)),
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
		err = es.TranslateError(res.StatusCode, &esres.Error)
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
