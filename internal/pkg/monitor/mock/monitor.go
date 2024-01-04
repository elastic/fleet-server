// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mock

import (
	"context"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/stretchr/testify/mock"
)

// MockSubscription implements monitor.Subscription
type MockSubscription struct {
	mock.Mock
}

func NewMockSubscription() *MockSubscription {
	return &MockSubscription{}
}

func (m *MockSubscription) Output() <-chan []es.HitT {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(<-chan []es.HitT)
}

// MockMonitor implements monitor.SimpleMonitor and monitor.Monitor
type MockMonitor struct {
	mock.Mock
}

func NewMockMonitor() *MockMonitor {
	return &MockMonitor{}
}

func (m *MockMonitor) Subscribe() monitor.Subscription {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(monitor.Subscription)
}

func (m *MockMonitor) Unsubscribe(s monitor.Subscription) {
	m.Called(s)
}

func (m *MockMonitor) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMonitor) GetCheckpoint() sqn.SeqNo {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(sqn.SeqNo)
}

func (m *MockMonitor) Output() <-chan []es.HitT {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(<-chan []es.HitT)
}

func (m *MockMonitor) State() client.UnitState {
	args := m.Called()
	return args.Get(0).(client.UnitState)
}
