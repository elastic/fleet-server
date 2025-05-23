// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package dl

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func TestFindAgent_NewModel(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetAgents)

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	policyID := uuid.Must(uuid.NewV4()).String()
	agentID := uuid.Must(uuid.NewV4()).String()

	wantOutputs := map[string]*model.PolicyOutput{
		"default": {
			Type:   "elasticsearch",
			APIKey: "TestFindNewModelAgent_APIKey",
			ToRetireAPIKeyIds: []model.ToRetireAPIKeyIdsItems{
				{
					ID:        "TestFindNewModelAgent_APIKeyID_invalidated",
					RetiredAt: "TestFindNewModelAgent_APIKeyID_invalidated_at"},
			},
			APIKeyID:        "TestFindNewModelAgent_APIKeyID",
			PermissionsHash: "TestFindNewModelAgent_PermisPolicysionsHash",
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
		ctx, index, agentID, body, bulk.WithRefresh())
	require.NoError(t, err)

	agent, err := FindAgent(
		ctx, bulker, QueryAgentByID, FieldID, agentID, WithIndexName(index))
	require.NoError(t, err)

	assert.Equal(t, agentID, agent.Id)
	assert.Equal(t, wantOutputs, agent.Outputs)
}
