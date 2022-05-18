// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package sleep provides a sleep/wait mechanism that can be cancelled.
package sleep

import (
	"context"
	"time"
)

// WithContext will sleep for the passed duration or return early if the context was cancelled.
func WithContext(ctx context.Context, dur time.Duration) error {
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
