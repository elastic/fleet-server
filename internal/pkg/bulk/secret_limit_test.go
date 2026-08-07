// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/stretchr/testify/require"
)

// blockingTransport is an http.RoundTripper that blocks until gate is closed
// and tracks how many requests are currently in-flight.
type blockingTransport struct {
	gate     chan struct{}
	inFlight atomic.Int64
}

func (m *blockingTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	m.inFlight.Add(1)
	defer m.inFlight.Add(-1)
	<-m.gate
	h := http.Header{}
	h.Set("X-Elastic-Product", "Elasticsearch")
	body := `{"value":"test"}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func newTestBulkerWithTransport(t *testing.T, transport http.RoundTripper, opts ...BulkOpt) *Bulker {
	t.Helper()
	esClient, err := elasticsearch.NewClient(elasticsearch.Config{
		Transport: transport,
		Addresses: []string{"http://localhost:9200"},
	})
	require.NoError(t, err)
	return NewBulker(esClient, nil, opts...)
}

// TestReadSecretsLimitsConcurrency verifies that WithMaxConcurrentSecretReads(1)
// allows at most one ReadSecret HTTP call in-flight at a time across concurrent
// ReadSecrets callers.
func TestReadSecretsLimitsConcurrency(t *testing.T) {
	mt := &blockingTransport{gate: make(chan struct{})}
	b := newTestBulkerWithTransport(t, mt, WithMaxConcurrentSecretReads(1))

	var wg sync.WaitGroup
	errs := make([]error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = b.ReadSecrets(context.Background(), []string{"id1"})
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = b.ReadSecrets(context.Background(), []string{"id2"})
	}()

	// Spin until at least one request is in the transport.
	for mt.inFlight.Load() < 1 {
		// wait for the first goroutine to enter the transport
	}

	// With semaphore capacity 1, the second goroutine is blocked on Acquire
	// and cannot have entered the transport yet.
	require.Equal(t, int64(1), mt.inFlight.Load())

	// Unblock both goroutines and wait for them to finish.
	close(mt.gate)
	wg.Wait()

	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
}

// TestReadSecretsContextCancelledWhileWaiting verifies that ReadSecrets returns
// context.Canceled immediately when the semaphore is full and the caller's context
// is already cancelled.
func TestReadSecretsContextCancelledWhileWaiting(t *testing.T) {
	mt := &blockingTransport{gate: make(chan struct{})}
	defer close(mt.gate)

	b := newTestBulkerWithTransport(t, mt, WithMaxConcurrentSecretReads(1))

	// Manually hold the only semaphore slot so ReadSecrets must wait.
	err := b.readSecretsLimit.Acquire(context.Background(), 1)
	require.NoError(t, err)
	defer b.readSecretsLimit.Release(1)

	// Call ReadSecrets with an already-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = b.ReadSecrets(ctx, []string{"id1"})
	require.ErrorIs(t, err, context.Canceled)
}

// TestReadSecretsNoLimitWhenZero verifies that WithMaxConcurrentSecretReads(0)
// disables the concurrency limit: readSecretsLimit is nil and ReadSecrets
// completes without blocking.
func TestReadSecretsNoLimitWhenZero(t *testing.T) {
	mt := &blockingTransport{gate: make(chan struct{})}
	close(mt.gate) // unblocked so ReadSecrets returns immediately

	b := newTestBulkerWithTransport(t, mt, WithMaxConcurrentSecretReads(0))

	require.Nil(t, b.readSecretsLimit)

	_, err := b.ReadSecrets(context.Background(), []string{"id1"})
	require.NoError(t, err)
}

// TestReadSecretsDefaultConcurrency verifies that a Bulker created without
// WithMaxConcurrentSecretReads initialises readSecretsLimit with the default
// capacity of defaultMaxConcurrentSecretReads (32). It confirms the capacity
// indirectly: after filling all slots via concurrent ReadSecrets calls that
// block in the transport, an additional Acquire with a cancelled context
// returns context.Canceled immediately.
func TestReadSecretsDefaultConcurrency(t *testing.T) {
	mt := &blockingTransport{gate: make(chan struct{})}

	// No WithMaxConcurrentSecretReads option → uses defaultMaxConcurrentSecretReads.
	b := newTestBulkerWithTransport(t, mt)

	require.NotNil(t, b.readSecretsLimit)

	// Launch defaultMaxConcurrentSecretReads goroutines, each calling ReadSecrets
	// with a single unique secret ID. Each goroutine will acquire one semaphore
	// slot and block in the transport, filling all capacity.
	var wg sync.WaitGroup
	for i := range defaultMaxConcurrentSecretReads {
		wg.Go(func() {
			_, _ = b.ReadSecrets(context.Background(), []string{fmt.Sprintf("id%d", i)})
		})
	}

	// Spin until all slots are occupied.
	for mt.inFlight.Load() < int64(defaultMaxConcurrentSecretReads) {
		// wait for all goroutines to enter the transport
	}

	// The semaphore is now full; a cancelled-context acquire must return immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := b.readSecretsLimit.Acquire(ctx, 1)
	require.ErrorIs(t, err, context.Canceled)

	// Unblock all goroutines.
	close(mt.gate)
	wg.Wait()
}
