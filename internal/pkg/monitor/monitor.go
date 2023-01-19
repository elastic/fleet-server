// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package monitor provides a way to track new/updated documents in an Elasticsearch index.
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
	"github.com/elastic/fleet-server/v7/internal/pkg/gcheckpt"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultPollTimeout    = 4 * time.Minute // default long poll timeout
	defaultSeqNo          = int64(-1)       //nolint:deadcode,varcheck // the _seq_no in elasticsearch start with 0
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

// GlobalCheckpointProvider provides SeqNo.
type GlobalCheckpointProvider interface {
	GetCheckpoint() sqn.SeqNo
}

// BaseMonitor is the monitor's interface implemented by SimpleMonitor and Monitor
type BaseMonitor interface {
	GlobalCheckpointProvider

	// Run runs the monitor
	Run(ctx context.Context) error
}

// SimpleMonitor monitors for new documents in an index.
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

// Option is a functional configuration option.
type Option func(SimpleMonitor)

// NewSimple creates new SimpleMonitor.
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

// WithFetchSize sets the fetch size of the monitor.
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

// WithExpiration adds the expiration field to the monitor query.
func WithExpiration(withExpiration bool) Option {
	return func(m SimpleMonitor) {
		m.(*simpleMonitorT).withExpiration = withExpiration
	}
}

// WithReadyChan allows to pass the channel that will signal when monitor is ready.
func WithReadyChan(readyCh chan error) Option {
	return func(m SimpleMonitor) {
		m.(*simpleMonitorT).readyCh = readyCh
	}
}

// Output returns the output channel for the monitor.
func (m *simpleMonitorT) Output() <-chan []es.HitT {
	return m.outCh
}

// GetCheckpoint implements GlobalCheckpointProvider interface.
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
	m.log.Info().Msg("starting index monitor")
	defer func() {
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		m.log.Info().Err(err).Msg("index monitor exited")
	}()

	defer func() {
		if m.readyCh != nil {
			m.readyCh <- err
		}
	}()

	// Get initial global checkpoint
	var checkpoint sqn.SeqNo
	checkpoint, err = gcheckpt.Query(ctx, m.monCli, m.index)
	if err != nil {
		m.log.Error().Err(err).Msg("failed to initialize the global checkpoints")
		return err
	}
	m.storeCheckpoint(checkpoint)
	m.log.Debug().Ints64("checkpoint", checkpoint).Msg("initial checkpoint")

	// Signal the monitor is ready
	if m.readyCh != nil {
		m.readyCh <- nil
		m.readyCh = nil
	}

	for {
		checkpoint := m.loadCheckpoint()

		// Wait for checkpoint advance, long poll.
		// It returns only if there are new documents fully indexed with _seq_no greater than the passed checkpoint value
		// or the timeout (long poll interval).
		newCheckpoint, err := gcheckpt.WaitAdvance(ctx, m.monCli, m.index, checkpoint, m.pollTimeout)
		if err != nil {
			if errors.Is(err, es.ErrIndexNotFound) {
				// Wait until created
				m.log.Debug().Msgf("index not found, poll again in %v", retryDelay)
			} else if errors.Is(err, es.ErrTimeout) {
				// Timed out, wait again
				m.log.Debug().Msg("timeout on global checkpoints advance, poll again")
				// Loop back to the checkpoint "wait advance" without delay
				continue
			} else if errors.Is(err, context.Canceled) {
				m.log.Info().Msg("context closed waiting for global checkpoints advance")
				// Exit run
				return err
			} else {
				// Log the error and keep trying
				m.log.Info().Err(err).Msg("failed on waiting for global checkpoints advance")
			}

			// Delay next attempt
			err = sleep.WithContext(ctx, retryDelay)
			if err != nil {
				return err
			}
			// Loop back to the checkpoint "wait advance" after the retry delay
			continue
		}

		// This is an example of steps for fetching the documents without "holes" (not-yet-indexed documents in between)
		// as recommended by Elasticsearch team on August 25th, 2021
		// 1. Call Global checkpoints = 5
		// 2. Search = 1, 2, 3, 5.
		// 3. Manual refresh
		// 4. Search and get 4,5
		// 5. Return to step 1

		// Fetch up to the new checkpoint.
		//
		// The fetch happens at least once.
		// The fetch repeats until there is no more documents to fetch.

		// Set count to max fetch size (m.fetchSize) initially, so the fetch happens at least once.
		count := m.fetchSize
		for count == m.fetchSize {
			// Fetch the documents between the last known checkpoint and the new checkpoint value received from "wait advance".
			hits, err := m.fetch(ctx, checkpoint, newCheckpoint)
			if err != nil {
				m.log.Error().Err(err).Msg("failed checking new documents")
				break
			}

			// Notify call updates m.checkpoint as max(_seq_no) from the fetched hits
			count = m.notify(ctx, hits)
			m.log.Debug().Int("count", count).Msg("hits found after notify")

			// If the number of fetched documents is the same as the max fetch size, then it's possible there are more documents to fetch.
			if count == m.fetchSize {
				// Get the latest checkpoint value for the next fetch iteration.
				checkpoint = m.loadCheckpoint()
			} else {
				// If the fetched number of documents is less than the max fetched size, then it is a final fetch for new checkpoint.
				// Update the monitor checkpoint value from the checkpoint "wait advance" response.
				//
				// This avoids the situation where the actions monitor checkpoint gets out of sync with the index checkpoint,
				// due to the index checkpoint being incremented by elasticsearch upon deleting the document.
				//
				// This fixes the issue https://github.com/elastic/fleet-server/issues/2205.
				// The root cause of the issue was the monitor implementation was not correctly accounting for the index
				// checkpoint increment when the action document is deleted from the index.
				m.storeCheckpoint(newCheckpoint)
			}
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

func (m *simpleMonitorT) fetch(ctx context.Context, checkpoint, maxCheckpoint sqn.SeqNo) ([]es.HitT, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Run check query that detects that there are new documents available
	params := map[string]interface{}{
		dl.FieldSeqNo:    checkpoint.Value(),
		dl.FieldMaxSeqNo: maxCheckpoint.Value(),
	}
	if m.withExpiration {
		params[dl.FieldExpiration] = now
	}

	hits, err := m.search(ctx, m.tmplQuery, params, maxCheckpoint)
	if err != nil {
		return nil, err
	}

	return hits, nil
}

func (m *simpleMonitorT) search(ctx context.Context, tmpl *dsl.Tmpl, params map[string]interface{}, seqNos sqn.SeqNo) ([]es.HitT, error) {
	query, err := tmpl.Render(params)
	if err != nil {
		return nil, err
	}

	res, err := m.esCli.FleetSearch(
		m.index,
		m.esCli.FleetSearch.WithContext(ctx),
		m.esCli.FleetSearch.WithBody(bytes.NewBuffer(query)),
		m.esCli.FleetSearch.WithWaitForCheckpoints(seqNos.String()),
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
			m.log.Debug().Msg(es.ErrIndexNotFound.Error())
			return nil, nil
		}
		return nil, err
	}

	return esres.Hits.Hits, nil
}

// Prepares minimal query to do the quick check without reading all matches full documents
func (m *simpleMonitorT) prepareCheckQuery() (*dsl.Tmpl, error) {
	tmpl, root := m.prepareCommon(false)

	root.Source().Includes(dl.FieldSeqNo)
	root.Size(1)

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}
	return tmpl, nil
}

// Prepares full documents query
func (m *simpleMonitorT) prepareQuery() (*dsl.Tmpl, error) {
	tmpl, root := m.prepareCommon(true)
	root.Size(uint64(m.fetchSize))
	root.Sort().SortOrder(fieldSeqNo, dsl.SortAscend)

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}
	return tmpl, nil
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
