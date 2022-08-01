// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package dl

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestFindOfflineAgents(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetAgents)

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	policyID := uuid.Must(uuid.NewV4()).String()
	dayOld := now.Add(-24 * time.Hour).Format(time.RFC3339)
	dayOldID := uuid.Must(uuid.NewV4()).String()
	body, err := json.Marshal(model.Agent{
		PolicyID:          policyID,
		Active:            true,
		LastCheckin:       dayOld,
		LastCheckinStatus: "",
		UpdatedAt:         dayOld,
		EnrolledAt:        nowStr,
	})
	require.NoError(t, err)
	_, err = bulker.Create(ctx, index, dayOldID, body, bulk.WithRefresh())
	require.NoError(t, err)

	twoDayOld := now.Add(-48 * time.Hour).Format(time.RFC3339)
	twoDayOldID := uuid.Must(uuid.NewV4()).String()
	body, err = json.Marshal(model.Agent{
		PolicyID:          policyID,
		Active:            true,
		LastCheckin:       twoDayOld,
		LastCheckinStatus: "",
		UpdatedAt:         twoDayOld,
		EnrolledAt:        nowStr,
	})
	require.NoError(t, err)
	_, err = bulker.Create(ctx, index, twoDayOldID, body, bulk.WithRefresh())
	require.NoError(t, err)

	// not active (should not be included)
	notActiveID := uuid.Must(uuid.NewV4()).String()
	body, err = json.Marshal(model.Agent{
		PolicyID:          policyID,
		Active:            false,
		LastCheckin:       twoDayOld,
		LastCheckinStatus: "",
		UpdatedAt:         twoDayOld,
		EnrolledAt:        nowStr,
	})
	require.NoError(t, err)
	_, err = bulker.Create(ctx, index, notActiveID, body, bulk.WithRefresh())
	require.NoError(t, err)

	threeDayOld := now.Add(-48 * time.Hour).Format(time.RFC3339)
	threeDayOldID := uuid.Must(uuid.NewV4()).String()
	body, err = json.Marshal(model.Agent{
		PolicyID:          policyID,
		Active:            true,
		LastCheckin:       threeDayOld,
		LastCheckinStatus: "",
		UpdatedAt:         threeDayOld,
		EnrolledAt:        nowStr,
	})
	require.NoError(t, err)
	_, err = bulker.Create(ctx, index, threeDayOldID, body, bulk.WithRefresh())
	require.NoError(t, err)

	// add agent on a different policy; should not be returned (3 days old)
	otherPolicyID := uuid.Must(uuid.NewV4()).String()
	otherID := uuid.Must(uuid.NewV4()).String()
	body, err = json.Marshal(model.Agent{
		PolicyID:          otherPolicyID,
		Active:            true,
		LastCheckin:       threeDayOld,
		LastCheckinStatus: "",
		UpdatedAt:         threeDayOld,
		EnrolledAt:        nowStr,
	})
	require.NoError(t, err)
	_, err = bulker.Create(ctx, index, otherID, body, bulk.WithRefresh())
	require.NoError(t, err)

	agents, err := FindOfflineAgents(ctx, bulker, policyID, 36*time.Hour, WithIndexName(index))
	require.NoError(t, err)
	require.Len(t, agents, 2)
	assert.EqualValues(t, []string{twoDayOldID, threeDayOldID}, []string{agents[0].Id, agents[1].Id})
}

func TestFindAgent_NewModel(t *testing.T) {
	index, bulker := ftesting.SetupCleanIndex(context.Background(), t, FleetAgents)

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	policyID := uuid.Must(uuid.NewV4()).String()
	agentID := uuid.Must(uuid.NewV4()).String()

	wantOutputs := map[string]*model.PolicyOutput{
		"default": {
			APIKey: "TestFindNewModelAgent_APIKey",
			ToRetireAPIKeys: []model.ToRetireAPIKeysItems{
				{
					ID:        "TestFindNewModelAgent_APIKeyID_invalidated",
					RetiredAt: "TestFindNewModelAgent_APIKeyID_invalidated_at"},
			},
			APIKeyID:              "TestFindNewModelAgent_APIKeyID",
			PolicyPermissionsHash: "TestFindNewModelAgent_PolicyPermissionsHash",
		},
	}
	body, err := json.Marshal(model.Agent{
		PolicyID:          policyID,
		Active:            true,
		LastCheckin:       nowStr,
		LastCheckinStatus: "",
		UpdatedAt:         nowStr,
		EnrolledAt:        nowStr,
		Outputs:           wantOutputs,
	})
	require.NoError(t, err)

	_, err = bulker.Create(
		context.Background(), index, agentID, body, bulk.WithRefresh())
	require.NoError(t, err)

	agent, err := FindAgent(
		context.Background(), bulker, QueryAgentByID, FieldID, agentID, WithIndexName(index))
	require.NoError(t, err)

	assert.Equal(t, agentID, agent.Id)
	assert.Equal(t, wantOutputs, agent.Outputs)
}
