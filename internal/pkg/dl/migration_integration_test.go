// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package dl

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func createSomeAgents(t *testing.T, n int, apiKey bulk.APIKey, index string, bulker bulk.Bulk) []string {
	t.Helper()

	var createdAgents []string

	for i := 0; i < n; i++ {
		outputAPIKey := bulk.APIKey{
			ID:  fmt.Sprint(apiKey.ID, i),
			Key: fmt.Sprint(apiKey.Key, i),
		}

		now := time.Now().UTC()
		nowStr := now.Format(time.RFC3339)

		agentID := uuid.Must(uuid.NewV4()).String()
		policyID := uuid.Must(uuid.NewV4()).String()

		agentModel := model.Agent{
			PolicyID:                    policyID,
			Active:                      true,
			LastCheckin:                 nowStr,
			LastCheckinStatus:           "",
			UpdatedAt:                   nowStr,
			EnrolledAt:                  nowStr,
			DefaultAPIKeyID:             outputAPIKey.ID,
			DefaultAPIKey:               outputAPIKey.Agent(),
			PolicyOutputPermissionsHash: fmt.Sprint("a_output_permission_SHA_", i),
			DefaultAPIKeyHistory: []model.ToRetireAPIKeysItems{
				{
					ID:        "old_" + outputAPIKey.ID,
					RetiredAt: now.Add(-5 * time.Minute).Format(time.RFC3339),
				},
			},
		}

		body, err := json.Marshal(agentModel)
		require.NoError(t, err)

		_, err = bulker.Create(
			context.Background(), index, agentID, body, bulk.WithRefresh())
		require.NoError(t, err)

		createdAgents = append(createdAgents, agentID)
	}

	return createdAgents
}

func createSomePolicies(t *testing.T, n int, index string, bulker bulk.Bulk) []string {
	t.Helper()

	var created []string

	for i := 0; i < n; i++ {
		now := time.Now().UTC()
		nowStr := now.Format(time.RFC3339)

		policyModel := model.Policy{
			ESDocument:         model.ESDocument{},
			CoordinatorIdx:     int64(i),
			Data:               nil,
			DefaultFleetServer: false,
			PolicyID:           fmt.Sprint(i),
			RevisionIdx:        1,
			Timestamp:          nowStr,
			UnenrollTimeout:    0,
		}

		body, err := json.Marshal(policyModel)
		require.NoError(t, err)

		policyDocID, err := bulker.Create(
			context.Background(), index, "", body, bulk.WithRefresh())
		require.NoError(t, err)

		created = append(created, policyDocID)
	}

	return created
}

func TestPolicyCoordinatorIdx(t *testing.T) {
	index, bulker := ftesting.SetupCleanIndex(context.Background(), t, FleetPolicies)

	docIDs := createSomePolicies(t, 25, index, bulker)

	migrated, err := migrate(context.Background(), bulker, migratePolicyCoordinatorIdx)
	require.NoError(t, err)

	require.Equal(t, len(docIDs), migrated)

	for i := range docIDs {
		policies, err := QueryLatestPolicies(
			context.Background(), bulker, WithIndexName(index))
		if err != nil {
			assert.NoError(t, err, "failed to query latest policies") // we want to continue even if a single agent fails
			continue
		}

		var got model.Policy
		for _, p := range policies {
			if p.PolicyID == fmt.Sprint(i) {
				got = p
			}
		}

		assert.Equal(t, int64(i+1), got.CoordinatorIdx)
	}
}

func TestMigrateOutputs(t *testing.T) {
	index, bulker := ftesting.SetupCleanIndex(context.Background(), t, FleetAgents)
	apiKey := bulk.APIKey{
		ID:  fmt.Sprint("testAgent_"),
		Key: fmt.Sprint("testAgent_key_"),
	}

	agentIDs := createSomeAgents(t, 10, apiKey, index, bulker)

	migratedAgents, err := migrate(context.Background(), bulker, migrateAgentOutputs)
	require.NoError(t, err)

	assert.Equal(t, len(agentIDs), migratedAgents)

	for i, id := range agentIDs {
		wantOutputType := "elasticsearch"
		wantAPIKey := bulk.APIKey{
			ID:  fmt.Sprint(apiKey.ID, i),
			Key: fmt.Sprint(apiKey.Key, i),
		}

		got, err := FindAgent(
			context.Background(), bulker, QueryAgentByID, FieldID, id, WithIndexName(index))
		if err != nil {
			assert.NoError(t, err, "failed to find agent ID %q", id) // we want to continue even if a single agent fails
			continue
		}

		// Assert new fields
		require.Len(t, got.Outputs, 1)
		assert.Equal(t, wantAPIKey.Agent(), got.Outputs["default"].APIKey)
		assert.Equal(t, wantAPIKey.ID, got.Outputs["default"].APIKeyID)
		assert.Equal(t, wantAPIKey.Agent(), got.Outputs["default"].APIKey)
		assert.Equal(t, wantOutputType, got.Outputs["default"].Type)
		assert.Equal(t,
			fmt.Sprint("a_output_permission_SHA_", i),
			got.Outputs["default"].PolicyPermissionsHash)

		// Assert deprecated fields
		assert.Empty(t, got.DefaultAPIKey)
		assert.Empty(t, got.DefaultAPIKey)
		assert.Empty(t, got.PolicyOutputPermissionsHash)
		assert.Nil(t, got.DefaultAPIKeyHistory)
	}
}
