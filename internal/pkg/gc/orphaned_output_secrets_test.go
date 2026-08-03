// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package gc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestOutputSecretIsReferenced(t *testing.T) {
	candidate := policy.OutputSecretCandidate{
		OutputName: "default",
		SecretID:   "candidate-secret",
		SecretRef:  "$co.elastic.secret{candidate-secret}",
	}

	tests := []struct {
		name  string
		agent model.Agent
		want  bool
	}{
		{
			name: "current output reference",
			agent: model.Agent{Outputs: map[string]*model.PolicyOutput{
				"default": {APIKey: candidate.SecretRef},
			}},
			want: true,
		},
		{
			name: "retired output reference",
			agent: model.Agent{Outputs: map[string]*model.PolicyOutput{
				"other": {ToRetireAPIKeyIds: []model.ToRetireAPIKeyIdsItems{{SecretID: candidate.SecretID}}},
			}},
			want: true,
		},
		{
			name: "unreferenced",
			agent: model.Agent{Outputs: map[string]*model.PolicyOutput{
				"default": {APIKey: "$co.elastic.secret{different-secret}"},
			}},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, outputSecretIsReferenced(&tc.agent, candidate))
		})
	}
}

func TestOrphanedOutputSecretReconcilerRequiresTwoUnreferencedObservations(t *testing.T) {
	ctx := context.Background()
	bulker := ftesting.NewMockBulk()
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	candidate := policy.OutputSecretCandidate{
		AgentID:    "agent-id",
		OutputName: "default",
		SecretID:   "candidate-secret",
		SecretRef:  "$co.elastic.secret{candidate-secret}",
	}
	agentSource, err := json.Marshal(model.Agent{Outputs: map[string]*model.PolicyOutput{}})
	require.NoError(t, err)
	bulker.On("ReadRaw", mock.Anything, dl.FleetAgents, candidate.AgentID, mock.Anything).
		Return(&bulk.MgetResponseItem{Found: true, Source: agentSource}, nil).Twice()
	bulker.On("DeleteSecret", mock.Anything, candidate.SecretID).Return(nil).Once()

	reconciler := NewOrphanedOutputSecretReconciler(bulker)
	reconciler.now = func() time.Time { return now }
	reconciler.pending[candidate.SecretID] = &outputSecretCandidateState{
		OutputSecretCandidate: candidate,
		createdAt:             now.Add(-reconciler.gracePeriod),
	}

	reconciler.reconcile(ctx)
	bulker.AssertNotCalled(t, "DeleteSecret", mock.Anything, candidate.SecretID)
	require.Contains(t, reconciler.pending, candidate.SecretID)

	now = now.Add(reconciler.confirmationPeriod)
	reconciler.reconcile(ctx)
	require.NotContains(t, reconciler.pending, candidate.SecretID)
	bulker.AssertExpectations(t)
}

func TestOrphanedOutputSecretReconcilerPreservesReferencedCandidate(t *testing.T) {
	ctx := context.Background()
	bulker := ftesting.NewMockBulk()
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	candidate := policy.OutputSecretCandidate{
		AgentID:    "agent-id",
		OutputName: "default",
		SecretID:   "candidate-secret",
		SecretRef:  "$co.elastic.secret{candidate-secret}",
	}
	agentSource, err := json.Marshal(model.Agent{Outputs: map[string]*model.PolicyOutput{
		"default": {APIKey: candidate.SecretRef},
	}})
	require.NoError(t, err)
	bulker.On("ReadRaw", mock.Anything, dl.FleetAgents, candidate.AgentID, mock.Anything).
		Return(&bulk.MgetResponseItem{Found: true, Source: agentSource}, nil).Once()

	reconciler := NewOrphanedOutputSecretReconciler(bulker)
	reconciler.now = func() time.Time { return now }
	reconciler.pending[candidate.SecretID] = &outputSecretCandidateState{
		OutputSecretCandidate: candidate,
		createdAt:             now.Add(-reconciler.gracePeriod),
	}

	reconciler.reconcile(ctx)
	require.NotContains(t, reconciler.pending, candidate.SecretID)
	bulker.AssertNotCalled(t, "DeleteSecret", mock.Anything, candidate.SecretID)
	bulker.AssertExpectations(t)
}

func TestOrphanedOutputSecretReconcilerRetriesReadErrors(t *testing.T) {
	ctx := context.Background()
	bulker := ftesting.NewMockBulk()
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	candidate := policy.OutputSecretCandidate{
		AgentID:  "agent-id",
		SecretID: "candidate-secret",
	}
	bulker.On("ReadRaw", mock.Anything, dl.FleetAgents, candidate.AgentID, mock.Anything).
		Return((*bulk.MgetResponseItem)(nil), errors.New("read failed")).Once()

	reconciler := NewOrphanedOutputSecretReconciler(bulker)
	reconciler.now = func() time.Time { return now }
	reconciler.pending[candidate.SecretID] = &outputSecretCandidateState{
		OutputSecretCandidate: candidate,
		createdAt:             now.Add(-reconciler.gracePeriod),
	}

	reconciler.reconcile(ctx)
	require.Contains(t, reconciler.pending, candidate.SecretID)
	require.True(t, reconciler.pending[candidate.SecretID].firstUnreferencedAt.IsZero())
	bulker.AssertNotCalled(t, "DeleteSecret", mock.Anything, candidate.SecretID)
	bulker.AssertExpectations(t)
}
