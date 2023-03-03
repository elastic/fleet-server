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
		expectedState client.UnitState
	}{
		{
			title: "healthy",
			searchResult: &es.ResultT{
				Aggregations: map[string]es.Aggregation{
					dl.FieldPolicyID: es.Aggregation{},
				},
			},
			expectedState: client.UnitStateHealthy,
		},
		{
			title:         "index not found",
			searchResult:  nil,
			searchErr:     es.ErrIndexNotFound,
			expectedState: client.UnitStateStarting,
		},
		{
			title:         "failed to connect with Elasticsearch",
			searchResult:  nil,
			searchErr:     errors.New("some unexpected error"),
			expectedState: client.UnitStateFailed,
		},
	}

	searchArguments := []any{mock.Anything, ".fleet-policies", mock.Anything, mock.Anything}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			bulker := ftesting.NewMockBulk()
			bulker.On("Search", searchArguments...).Return(c.searchResult, c.searchErr)

			reporter := &FakeReporter{}

			sm := NewStandAloneSelfMonitor(bulker, reporter)
			assert.Equal(t, sm.State(), client.UnitStateStarting)

			state := sm.check(context.Background())

			assert.Equal(t, state, c.expectedState)
			assert.Equal(t, state, reporter.state, "reported state should be the same")
		})
	}
}
