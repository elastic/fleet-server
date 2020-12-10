// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

import (
	"bytes"
	"context"
	"encoding/json"
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

// Monitor monitors for new documents in an index
type Monitor interface {
	GlobalCheckpointProvider

	// Run runs the monitor
	Run(ctx context.Context) error

	// Output is the channel the monitor send new documents to
	Output() <-chan []es.HitT
}

// monitorT monitors for new documents in an index
type monitorT struct {
	cli  *elasticsearch.Client
	tmpl *dsl.Tmpl

	index          string
	checkInterval  time.Duration
	withExpiration bool

	checkpoint int64 // index global checkpoint

	log zerolog.Logger

	outCh chan []es.HitT
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
		outCh:          make(chan []es.HitT, 1),
	}

	for _, opt := range opts {
		opt(m)
	}

	m.log = log.With().Str("index", m.index).Str("ctx", "index monitor").Logger()

	tmpl, err := m.prepareQuery()
	if err != nil {
		return nil, err
	}
	m.tmpl = tmpl

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

// Output output channel for the monitor
func (m *monitorT) Output() <-chan []es.HitT {
	return m.outCh
}

// GetCheckpoint implements GlobalCheckpointProvider interface
func (m *monitorT) GetCheckpoint() int64 {
	return m.loadCheckpoint()
}

func (m *monitorT) storeCheckpoint(val int64) {
	m.log.Debug().Int64("checkpoint", val).Msg("Updated checkpoint")
	atomic.StoreInt64(&m.checkpoint, val)
}

func (m *monitorT) loadCheckpoint() int64 {
	return atomic.LoadInt64(&m.checkpoint)
}

// Run runs monitor.
func (m *monitorT) Run(ctx context.Context) (err error) {
	m.log.Info().Msg("Start")
	defer func() {
		m.log.Info().Err(err).Msg("Exited")
	}()

	// Initialize global checkpoint from the index stats
	var checkpoint int64
	checkpoint, err = queryGlobalCheckpoint(ctx, m.cli, m.index)
	if err != nil {
		m.log.Error().Err(err).Msg("Failed to initialize the global checkpoint")
		return err
	}
	m.storeCheckpoint(checkpoint)

	// Start timer loop to check for global checkpoint changes
	t := time.NewTimer(m.checkInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// Check global checkout change
			m.checkGlobalCheckpoint(ctx)
			t.Reset(m.checkInterval)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *monitorT) checkGlobalCheckpoint(ctx context.Context) error {
	gcp, err := queryGlobalCheckpoint(ctx, m.cli, m.index)
	if err != nil {
		m.log.Error().Err(err).Msg("Failed to check the global checkpoint")
		return err
	}

	checkpoint := m.loadCheckpoint()
	if gcp > checkpoint {
		m.checkNewDocuments(ctx, checkpoint, gcp)
	}
	return nil
}

func (m *monitorT) checkNewDocuments(ctx context.Context, seqno, maxSeqNo int64) error {
	now := time.Now().UTC().Format(time.RFC3339)

	params := map[string]interface{}{
		dl.FieldSeqNo:    seqno,
		dl.FieldMaxSeqNo: maxSeqNo,
	}

	if m.withExpiration {
		params[dl.FieldExpiration] = now
	}

	query, err := m.tmpl.Render(params)
	if err != nil {
		return err
	}

	res, err := m.cli.Search(
		m.cli.Search.WithContext(ctx),
		m.cli.Search.WithIndex(m.index),
		m.cli.Search.WithBody(bytes.NewBuffer(query)),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var esres es.Response
	err = json.NewDecoder(res.Body).Decode(&esres)
	if err != nil {
		return err
	}

	if res.IsError() {
		return es.TranslateError(res.StatusCode, esres.Error)
	}

	hits := esres.Hits.Hits
	sz := len(hits)
	if sz > 0 {
		maxVal := hits[sz-1].SeqNo
		m.storeCheckpoint(maxVal)

		select {
		case m.outCh <- hits:
		case <-ctx.Done():
		}
	}
	return nil
}

func (m *monitorT) prepareQuery() (tmpl *dsl.Tmpl, err error) {
	tmpl = dsl.NewTmpl()

	root := dsl.NewRoot()
	root.Param(seqNoPrimaryTerm, true)

	filter := root.Query().Bool().Filter()
	filter.Range(fieldSeqNo, dsl.WithRangeGT(tmpl.Bind(fieldSeqNo)))
	filter.Range(fieldSeqNo, dsl.WithRangeLTE(tmpl.Bind(fieldMaxSeqNo)))
	if m.withExpiration {
		filter.Range(fieldExpiration, dsl.WithRangeGT(tmpl.Bind(fieldExpiration)))
	}

	root.Sort().SortOrder(fieldSeqNo, dsl.SortAscend)

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}
	return
}
