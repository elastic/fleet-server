// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestStandAloneSelfMonitor(t *testing.T) {
	cases := []struct {
		title         string
		searchResult  *es.ResultT
		searchErr     error
		initialState  client.UnitState
		expectedState client.UnitState
	}{
		{
			title: "healthy",
			searchResult: &es.ResultT{
				Aggregations: map[string]es.Aggregation{
					dl.FieldPolicyID: es.Aggregation{},
				},
			},
			initialState:  client.UnitStateStarting,
			expectedState: client.UnitStateHealthy,
		},
		{
			title:         "index not found",
			searchResult:  nil,
			searchErr:     es.ErrIndexNotFound,
			initialState:  client.UnitStateStarting,
			expectedState: client.UnitStateHealthy,
		},
		{
			title:         "index not found after being degraded",
			searchResult:  nil,
			searchErr:     es.ErrIndexNotFound,
			initialState:  client.UnitStateDegraded,
			expectedState: client.UnitStateHealthy,
		},
		{
			title:         "failed to connect with Elasticsearch",
			searchResult:  nil,
			searchErr:     errors.New("some unexpected error"),
			initialState:  client.UnitStateStarting,
			expectedState: client.UnitStateStarting,
		},
		{
			title:         "failed to connect with Elasticsearch after being healthy",
			searchResult:  nil,
			searchErr:     errors.New("some unexpected error"),
			initialState:  client.UnitStateHealthy,
			expectedState: client.UnitStateDegraded,
		},
		{
			title:         "failed to connect with Elasticsearch after being degraded",
			searchResult:  nil,
			searchErr:     errors.New("some unexpected error"),
			initialState:  client.UnitStateDegraded,
			expectedState: client.UnitStateDegraded,
		},
	}

	searchArguments := []any{mock.Anything, ".fleet-policies", mock.Anything, mock.Anything}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			bulker := ftesting.NewMockBulk()
			bulker.On("Search", searchArguments...).Return(c.searchResult, c.searchErr)
			emptyMap := make(map[string]string)
			bulker.On("GetRemoteOutputErrorMap").Return(emptyMap).Once()
			reporter := &FakeReporter{}

			sm := NewStandAloneSelfMonitor(bulker, reporter)
			sm.updateState(c.initialState, "test")

			sm.check(context.Background())
			state := sm.State()

			assert.Equal(t, c.expectedState, state)
			assert.Equal(t, state, reporter.state, "reported state should be the same")
		})
	}
}

func TestStandAloneSelfMonitorRemoteOutput(t *testing.T) {

	searchArguments := []any{mock.Anything, ".fleet-policies", mock.Anything, mock.Anything}

	bulker := ftesting.NewMockBulk()
	bulker.On("Search", searchArguments...).Return(&es.ResultT{
		Aggregations: map[string]es.Aggregation{
			dl.FieldPolicyID: es.Aggregation{},
		},
	}, nil)

	errorMap := make(map[string]string)
	errorMap["remote output"] = "error connecting to remote output"
	bulker.On("GetRemoteOutputErrorMap").Return(errorMap).Once()

	emptyMap := make(map[string]string)
	bulker.On("GetRemoteOutputErrorMap").Return(emptyMap).Once()

	reporter := &FakeReporter{}

	sm := NewStandAloneSelfMonitor(bulker, reporter)
	sm.updateState(client.UnitStateStarting, "test")

	sm.check(context.Background())
	state := sm.State()

	assert.Equal(t, client.UnitStateDegraded, state)
	assert.Equal(t, state, reporter.state, "reported state should be the same")

	// back to healthy
	sm.check(context.Background())
	state = sm.State()

	assert.Equal(t, client.UnitStateHealthy, state)
	assert.Equal(t, state, reporter.state, "reported state should be the same")
}
