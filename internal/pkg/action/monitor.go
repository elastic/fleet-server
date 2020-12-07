// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package action

import (
	"context"
	"sync/atomic"
	"time"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/dsl"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type GlobalCheckpointProvider interface {
	GetCheckpoint() int64
}

const (
	defaultCheckInterval = 1         // check every second for the new action
	defaultSeqNo         = int64(-1) // the _seq_no in elasticsearch start with 0
)

// Monitor monitors for new documents, theoretically can be applied to any index conforming the schema
type Monitor struct {
	bulker        bulk.Bulk
	tmpl          *dsl.Tmpl
	index         string
	checkInterval time.Duration

	checkpoint int64 // index global checkpoint

	log zerolog.Logger

	outCh chan []bulk.HitT
}

// MonitorOption monitor functional option
type MonitorOption func(*Monitor)

// NewMonitor creates new monitor
func NewMonitor(bulker bulk.Bulk, opts ...MonitorOption) (*Monitor, error) {
	tmpl, err := dl.PrepareAllAgentActionsQuery()
	if err != nil {
		return nil, err
	}

	m := &Monitor{
		bulker:        bulker,
		tmpl:          tmpl,
		index:         dl.FleetActions,
		checkInterval: defaultCheckInterval * time.Second,
		checkpoint:    defaultSeqNo,
		outCh:         make(chan []bulk.HitT, 1),
	}

	for _, opt := range opts {
		opt(m)
	}

	m.log = log.With().Str("index", m.index).Str("ctx", "docs monitor").Logger()

	return m, nil
}

// WithIndex sets the index name to monitor, default is .fleet-actoins
func WithIndex(index string) MonitorOption {
	return func(m *Monitor) {
		m.index = index
	}
}

// WithCheckInterval sets a periodic check interval
func WithCheckInterval(interval time.Duration) MonitorOption {
	return func(m *Monitor) {
		m.checkInterval = interval
	}
}

// Output output channel for the monitor
func (m *Monitor) Output() <-chan []bulk.HitT {
	return m.outCh
}

// GetCheckpoint implements GlobalCheckpointProvider interface
func (m *Monitor) GetCheckpoint() int64 {
	return m.loadCheckpoint()
}

func (m *Monitor) storeCheckpoint(val int64) {
	m.log.Debug().Int64("checkpoint", val).Msg("Updated checkpoint")
	atomic.StoreInt64(&m.checkpoint, val)
}

func (m *Monitor) loadCheckpoint() int64 {
	return atomic.LoadInt64(&m.checkpoint)
}

// Run runs monitor.
func (m *Monitor) Run(ctx context.Context) (err error) {
	m.log.Info().Msg("Start")
	defer func() {
		m.log.Info().Err(err).Msg("Exited")
	}()

	// Initialize global checkpoint from the index stats
	var checkpoint int64
	checkpoint, err = dl.QueryGlobalCheckpoint(ctx, m.bulker, m.index)
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

func (m *Monitor) checkGlobalCheckpoint(ctx context.Context) error {
	gcp, err := dl.QueryGlobalCheckpoint(ctx, m.bulker, m.index)
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

func (m *Monitor) checkNewDocuments(ctx context.Context, seqno, maxSeqNo int64) error {
	now := time.Now().UTC().Format(time.RFC3339)

	res, err := dl.Search(ctx, m.bulker, m.tmpl, m.index, map[string]interface{}{
		dl.FieldSeqNo:      seqno,
		dl.FieldMaxSeqNo:   maxSeqNo,
		dl.FieldExpiration: now,
	})
	if err != nil {
		return err
	}

	sz := len(res.Hits)
	if sz > 0 {
		maxVal := res.Hits[sz-1].SeqNo
		m.storeCheckpoint(maxVal)

		select {
		case m.outCh <- res.Hits:
		case <-ctx.Done():
		}
	}
	return nil
}
