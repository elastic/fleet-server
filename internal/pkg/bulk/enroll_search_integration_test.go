// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package bulk

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

// TestEnrollSearchDedup verifies that concurrent FindAgent searches sharing the
// same enrollment_id are de-duplicated within a single flush batch: exactly one
// request (the oldest, FIFO) is executed against ES and the rest receive
// ErrEnrollDuplicate so the agent handlers know to retry.
func TestEnrollSearchDedup(t *testing.T) {
	const (
		numConcurrent = 10
		// Set threshold high enough that the timer drives the flush, not item count.
		enrollThreshold = numConcurrent + 1
		enrollInterval  = 300 * time.Millisecond
	)

	ctx := t.Context()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	// enrollThreshold > numConcurrent ensures all goroutines land in one batch.
	index, bulker := SetupIndexWithBulk(ctx, t, testPolicy,
		WithEnrollFlushThresholdCount(enrollThreshold),
		WithEnrollFlushInterval(enrollInterval),
	)

	// Write a doc so the canonical search has something to find.
	sample := NewRandomSample()
	_, err := bulker.Create(ctx, index, "", sample.marshal(t), WithRefresh())
	require.NoError(t, err)

	dsl := []byte(`{"query":{"match_all":{}}}`)
	dedupeKey := "test-enrollment-id-dedup"

	errs := make([]error, numConcurrent)
	var wg sync.WaitGroup
	wg.Add(numConcurrent)
	for i := range numConcurrent {
		go func(i int) {
			defer wg.Done()
			_, searchErr := bulker.Search(ctx, index, dsl, WithDedupeKey(dedupeKey, index))
			errs[i] = searchErr
		}(i)
	}
	wg.Wait()

	var dupes, successes int
	for _, e := range errs {
		if errors.Is(e, ErrEnrollDuplicate) {
			dupes++
		} else {
			assert.NoError(t, e, "canonical request should not error")
			successes++
		}
	}

	assert.Equal(t, 1, successes, "exactly one canonical request should succeed")
	assert.Equal(t, numConcurrent-1, dupes, "all other requests should receive ErrEnrollDuplicate")
}

// TestEnrollSearchMissingIndex verifies that a Search with WithDedupeKey against a
// non-existent index does not fail with a "enroll search refresh failed" error.
// Before the fix, the pre-enrollment _refresh returned HTTP 404 for missing indices,
// which caused failQueue and permanent enrollment deadlock on fresh Serverless projects.
// With IgnoreUnavailable=true the refresh is a no-op; the msearch then returns a
// no-such-index error, which handleEnroll treats as "agent not found" and proceeds.
func TestEnrollSearchMissingIndex(t *testing.T) {
	ctx := t.Context()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	_, bulker := SetupIndexWithBulk(ctx, t, testPolicy,
		WithEnrollFlushThresholdCount(1),
		WithEnrollFlushInterval(300*time.Millisecond),
	)

	// Use a name that is guaranteed not to exist.
	missingIndex := "test-missing-index-" + xid.New().String()
	dsl := []byte(`{"query":{"match_all":{}}}`)

	_, err := bulker.Search(ctx, missingIndex, dsl, WithDedupeKey("some-enrollment-id", missingIndex))

	// The refresh must not fail (no "enroll search refresh failed" error).
	// The msearch will return an index-not-found error, which is the expected path.
	require.Error(t, err, "expected an error for missing index, not nil")
	assert.NotContains(t, err.Error(), "enroll search refresh failed",
		"refresh must not fail when index is missing (IgnoreUnavailable=true should silence the 404)")
}
