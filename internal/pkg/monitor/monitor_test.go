// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package monitor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/go-elasticsearch/v9"
	"github.com/stretchr/testify/require"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newESClient(t *testing.T, transport http.RoundTripper) *elasticsearch.Client {
	t.Helper()
	cli, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{"http://localhost:9200"},
		Transport: transport,
	})
	require.NoError(t, err)
	return cli
}

const shardRestoringBody = `{"error":{"type":"shard_restoring_exception","reason":"shard is being restored"}}`
const checkpointBody = `{"global_checkpoints":[0]}`

// TestSimpleMonitor_ShardRestoringInInitLoop verifies that when the ES global
// checkpoint API returns shard_restoring_exception during initialisation, the
// monitor does not surface ErrShardRestoring to the caller; instead it enters
// the retry-sleep path, which is immediately unblocked by context cancellation.
func TestSimpleMonitor_ShardRestoringInInitLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	var callCount int
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		callCount++
		h := make(http.Header)
		h.Set("X-Elastic-Product", "Elasticsearch")
		// Simulate shard_restoring_exception then cancel ctx so the retry
		// sleep unblocks immediately instead of waiting retryDelay.
		cancel()
		return &http.Response{
			StatusCode: http.StatusConflict,
			Body:       io.NopCloser(strings.NewReader(shardRestoringBody)),
			Header:     h,
		}, nil
	})

	esCli := newESClient(t, transport)
	mon, err := NewSimple("test-index", esCli, esCli, WithReadyChan(make(chan error, 1)))
	require.NoError(t, err)

	// Run converts context.Canceled to nil; ErrShardRestoring must not leak.
	require.NoError(t, mon.Run(ctx))
	require.Equal(t, 1, callCount, "expected exactly one ES call before context was cancelled")
}

// TestSimpleMonitor_ShardRestoringInPollLoop verifies that when the poll loop
// receives shard_restoring_exception the monitor retries instead of exiting.
// The first ES call succeeds (init), the second returns shard_restoring and
// cancels the context so the retry sleep unblocks immediately.
func TestSimpleMonitor_ShardRestoringInPollLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	var callCount int
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		callCount++
		h := make(http.Header)
		h.Set("X-Elastic-Product", "Elasticsearch")

		if callCount == 1 {
			// Init call: return a valid checkpoint so the monitor advances to
			// the poll loop and signals ready.
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(checkpointBody)),
				Header:     h,
			}, nil
		}

		// Poll call: return shard_restoring_exception then cancel ctx so the
		// retry sleep unblocks immediately.
		cancel()
		return &http.Response{
			StatusCode: http.StatusConflict,
			Body:       io.NopCloser(strings.NewReader(shardRestoringBody)),
			Header:     h,
		}, nil
	})

	esCli := newESClient(t, transport)
	readyCh := make(chan error, 1)
	mon, err := NewSimple("test-index", esCli, esCli, WithReadyChan(readyCh))
	require.NoError(t, err)

	// Run converts context.Canceled to nil; ErrShardRestoring must not leak.
	require.NoError(t, mon.Run(ctx))
	require.GreaterOrEqual(t, callCount, 2, "expected at least one init call and one poll call")

	// The ready signal must have been sent after the successful init.
	select {
	case readyErr := <-readyCh:
		require.NoError(t, readyErr)
	default:
		t.Fatal("monitor did not send on readyCh after successful init")
	}
}
