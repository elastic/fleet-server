// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// maxPending and apikeyMaxParallel size semaphores, and semaphore.NewWeighted
// panics on a negative size, so parseBulkOpts must never let a negative value
// through.
func TestParseBulkOptsRejectsNegativeConcurrencyLimits(t *testing.T) {
	opts := parseBulkOpts(WithMaxPending(-1), WithAPIKeyMaxParallel(-1))

	require.Equal(t, defaultMaxPending, opts.maxPending)
	require.Equal(t, defaultAPIKeyMaxParallel, opts.apikeyMaxParallel)
}
