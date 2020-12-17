package mock

import (
	"context"
	"sync"
	"sync/atomic"

	"fleet/internal/pkg/es"
	"fleet/internal/pkg/monitor"
)

var gMockIndexCounter uint64

type mockSubT struct {
	idx uint64
	c chan []es.HitT
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
		subs: make(map[uint64]*mockSubT),
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
		c: make(chan []es.HitT),
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
		subs := m.subs
		m.mut.RUnlock()

		var wg sync.WaitGroup
		wg.Add(len(subs))
		for _, s := range subs {
			go func(){
				defer wg.Done()
				select {
				case s.c <- hits:
				case <-ctx.Done():
				}
			}()
		}
		wg.Wait()
	}
}
