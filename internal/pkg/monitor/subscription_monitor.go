// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"github.com/rs/zerolog"

	"github.com/elastic/go-elasticsearch/v8"
	"golang.org/x/sync/errgroup"
)

var gCounter uint64

// Subscription is a subscription to get notified for new documents.
type Subscription interface {
	// Output is the channel the monitor send new documents to
	Output() <-chan []es.HitT
}

// Monitor monitors for new documents in an index and sends them to its subscriptions.
type Monitor interface {
	// The BaseMonitor methods
	BaseMonitor

	// Subscribe to get notified of documents
	Subscribe() Subscription

	// Unsubscribe from getting notifications on documents
	Unsubscribe(sub Subscription)
}

// subT is a subscription to get notified for new documents.
type subT struct {
	idx uint64
	c   chan []es.HitT
}

// Output returns the subscription channel.
func (s *subT) Output() <-chan []es.HitT {
	return s.c
}

// monitorT monitors for new documents in an index.
type monitorT struct {
	sm   SimpleMonitor
	mut  sync.RWMutex
	subs map[uint64]*subT
}

// New creates new subscription monitor.
func New(index string, esCli, monCli *elasticsearch.Client, opts ...Option) (Monitor, error) {
	sm, err := NewSimple(index, esCli, monCli, opts...)
	if err != nil {
		return nil, err
	}

	m := &monitorT{
		sm:   sm,
		subs: make(map[uint64]*subT),
	}

	return m, nil
}

// GetCheckpoint implements the GlobalCheckpointProvider interface.
func (m *monitorT) GetCheckpoint() sqn.SeqNo {
	return m.sm.GetCheckpoint()
}

// Subscribe returns a Subscription that is used to get notified of documents.
func (m *monitorT) Subscribe() Subscription {
	idx := atomic.AddUint64(&gCounter, 1)

	s := &subT{
		idx: idx,
		c:   make(chan []es.HitT, 1),
	}

	m.mut.Lock()
	m.subs[idx] = s
	m.mut.Unlock()
	return s
}

// Unsubscribe removes a subscription from the Monitor.
// The Subscription channel is not closed by Unsubscribe.
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

// Run starts the Monitor.
func (m *monitorT) Run(ctx context.Context) (err error) {
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return m.sm.Run(gctx)
	})

LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case hits := <-m.sm.Output():
			m.notify(ctx, hits)
		}
	}

	return g.Wait()
}

func (m *monitorT) notify(ctx context.Context, hits []es.HitT) {
	sz := len(hits)
	if sz > 0 {
		m.mut.RLock()
		var wg sync.WaitGroup
		wg.Add(len(m.subs))
		for _, s := range m.subs {
			go func(s *subT) {
				defer wg.Done()
				select {
				case s.c <- hits:
					zerolog.Ctx(ctx).Info().
						Str("ctx", "subscription monitor").
						Any("hits", hits).
						Msg("received notification")
				case <-ctx.Done():
					zerolog.Ctx(ctx).Error().
						Err(ctx.Err()).
						Str("ctx", "subscription monitor").
						Any("hits", hits).
						Msg("dropped notification")
				}
			}(s)
		}
		m.mut.RUnlock()
		wg.Wait()
	}
}
