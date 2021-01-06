// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mock

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"fleet-server/internal/pkg/es"
	"fleet-server/internal/pkg/monitor"
)

var gMockIndexCounter uint64

type mockSubT struct {
	idx uint64
	c   chan []es.HitT
}

func (s *mockSubT) Output() <-chan []es.HitT {
	return s.c
}

type MockIndexMonitor struct {
	checkpoint int64

	mut  sync.RWMutex
	subs map[uint64]*mockSubT
}

// NewMockIndexMonitor returns a mock monitor.
func NewMockIndexMonitor() *MockIndexMonitor {
	return &MockIndexMonitor{
		checkpoint: -1,
		subs:       make(map[uint64]*mockSubT),
	}
}

// GetCheckpoint returns the current checkpoint.
func (m *MockIndexMonitor) GetCheckpoint() int64 {
	return m.checkpoint
}

// Run does nothing as its not really running.
func (m *MockIndexMonitor) Run(ctx context.Context) error {
	return nil
}

// Subscribe to get notified of documents
func (m *MockIndexMonitor) Subscribe() monitor.Subscription {
	idx := atomic.AddUint64(&gMockIndexCounter, 1)

	s := &mockSubT{
		idx: idx,
		c:   make(chan []es.HitT),
	}

	m.mut.Lock()
	m.subs[idx] = s
	m.mut.Unlock()
	return s
}

// Unsubscribe from getting notifications on documents
func (m *MockIndexMonitor) Unsubscribe(sub monitor.Subscription) {
	s, ok := sub.(*mockSubT)
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

// Notify performs a mock notification to the subscribers
func (m *MockIndexMonitor) Notify(ctx context.Context, hits []es.HitT) {
	sz := len(hits)
	if sz > 0 {
		maxVal := hits[sz-1].SeqNo
		m.checkpoint = maxVal

		m.mut.RLock()
		var wg sync.WaitGroup
		wg.Add(len(m.subs))
		for _, s := range m.subs {
			go func(s *mockSubT) {
				defer wg.Done()
				lc, cn := context.WithTimeout(ctx, 5*time.Second)
				defer cn()
				select {
				case s.c <- hits:
				case <-lc.Done():
					err := ctx.Err()
					if err == context.DeadlineExceeded {
						panic(err)
					}
				}
			}(s)
		}
		m.mut.RUnlock()
		wg.Wait()
	}
}
