// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
)

type retryOptionT struct {
	sleep time.Duration
	count int
}

// RetryOption is an option to change retry behavior
type RetryOption func(o *retryOptionT)

// RetryFunc is the function to keep retrying
type RetryFunc func(context.Context) error

// RetrySleep adjust the sleep time between retries
func RetrySleep(sleep time.Duration) RetryOption {
	return func(o *retryOptionT) {
		o.sleep = sleep
	}
}

// RetryCount adjust the retry count
func RetryCount(count int) RetryOption {
	return func(o *retryOptionT) {
		o.count = count
	}
}

// Retry helper that can have sleep and max count
func Retry(t *testing.T, ctx context.Context, f RetryFunc, opts ...RetryOption) {
	t.Helper()
	o := retryOptionT{
		sleep: 100 * time.Millisecond,
		count: 3,
	}
	for _, opt := range opts {
		opt(&o)
	}
	var err error
	for i := 0; i < o.count; i++ {
		err = f(ctx)
		if err == nil {
			return
		}
		_ = sleep.WithContext(ctx, o.sleep)
	}
	t.Fatal(err)
}
