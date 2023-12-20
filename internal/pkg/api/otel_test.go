// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"

	"github.com/stretchr/testify/mock"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"
)

// mockCounter is a mock implementation of metric.Int64Counter and metric.Int64UpDownCounter
// It is used in unit tests to ensure any metrics instrumentation does not panic
type mockCounter struct {
	embedded.Int64Counter
	embedded.Int64UpDownCounter
	mock.Mock
}

func (m *mockCounter) Add(ctx context.Context, i int64, options ...metric.AddOption) {
	m.Called(ctx, i, options)
}

// Ensure that mockCounter implements the interface
var _ metric.Int64Counter = &mockCounter{}

func nopRouteStats() routeStats {
	counter := &mockCounter{}
	counter.On("Add", mock.Anything, mock.Anything, mock.Anything)
	return routeStats{
		active:   counter,
		total:    counter,
		errCount: counter,
		bodyIn:   counter,
		bodyOut:  counter,
	}
}
