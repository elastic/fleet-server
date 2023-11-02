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
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

const nowStr = "2022-08-12T16:50:05Z"

func createSomeAgents(t *testing.T, n int, apiKey bulk.APIKey, index string, bulker bulk.Bulk) []string {
	t.Helper()

	var createdAgents []string

	for i := 0; i < n; i++ {
		outputAPIKey := bulk.APIKey{
			ID:  fmt.Sprint(apiKey.ID, i),
			Key: fmt.Sprint(apiKey.Key, i),
		}

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
			DefaultAPIKeyHistory: []model.ToRetireAPIKeyIdsItems{
				{
					ID:        "old_" + outputAPIKey.ID,
					RetiredAt: nowStr,
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

	var policyData = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]interface{}{},
	}

	for i := 0; i < n; i++ {
		now := time.Now().UTC()
		nowStr := now.Format(time.RFC3339)

		policyModel := model.Policy{
			ESDocument:         model.ESDocument{},
			CoordinatorIdx:     int64(i),
			Data:               &policyData,
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

func TestMigrateOutputs_withDefaultAPIKeyHistory(t *testing.T) {
	now, err := time.Parse(time.RFC3339, nowStr)
	require.NoError(t, err, "could not parse time "+nowStr)
	timeNow = func() time.Time {
		return now
	}

	index, bulker := ftesting.SetupCleanIndex(context.Background(), t, FleetAgents)
	apiKey := bulk.APIKey{
		ID:  "testAgent_",
		Key: "testAgent_key_",
	}

	agentIDs := createSomeAgents(t, 25, apiKey, index, bulker)

	migratedAgents, err := migrate(context.Background(), bulker, migrateAgentOutputs)
	require.NoError(t, err)

	assert.Equal(t, len(agentIDs), migratedAgents)

	for i, id := range agentIDs {
		wantOutputType := "elasticsearch" //nolint:goconst // test cases have some duplication

		res, err := SearchWithOneParam(context.Background(), bulker, QueryAgentByID, index, FieldID, id)
		require.NoError(t, err)
		require.Len(t, res.Hits, 1)

		var got model.Agent
		err = res.Hits[0].Unmarshal(&got)
		require.NoError(t, err, "could not unmarshal ES document into model.Agent")

		gotDeprecatedFields := struct {
			// Deprecated. Use Outputs instead. API key the Elastic Agent uses to authenticate with elasticsearch
			DefaultAPIKey *string `json:"default_api_key,omitempty"`

			// Deprecated. Use Outputs instead. Default API Key History
			DefaultAPIKeyHistory []model.ToRetireAPIKeyIdsItems `json:"default_api_key_history,omitempty"`

			// Deprecated. Use Outputs instead. ID of the API key the Elastic Agent uses to authenticate with elasticsearch
			DefaultAPIKeyID *string `json:"default_api_key_id,omitempty"`

			// Deprecated. Use Outputs instead. The policy output permissions hash
			PolicyOutputPermissionsHash *string `json:"policy_output_permissions_hash,omitempty"`
		}{}
		err = res.Hits[0].Unmarshal(&gotDeprecatedFields)
		require.NoError(t, err, "could not unmarshal ES document into gotDeprecatedFields")

		wantToRetireAPIKeyIds := []model.ToRetireAPIKeyIdsItems{
			{
				// Current API should be marked to retire after the migration
				ID:        fmt.Sprintf("%s%d", apiKey.ID, i),
				RetiredAt: timeNow().UTC().Format(time.RFC3339)},
			{
				ID:        fmt.Sprintf("old_%s%d", apiKey.ID, i),
				RetiredAt: nowStr},
		}

		// Assert new fields
		require.Len(t, got.Outputs, 1)
		// Default API key is empty to force fleet-server to regenerate them.
		assert.Empty(t, got.Outputs["default"].APIKey)
		assert.Empty(t, got.Outputs["default"].APIKeyID)

		assert.Equal(t, wantOutputType, got.Outputs["default"].Type)
		assert.Equal(t,
			fmt.Sprint("a_output_permission_SHA_", i),
			got.Outputs["default"].PermissionsHash)

		// Assert ToRetireAPIKeyIds contains the expected values, regardless of the order.
		for _, want := range wantToRetireAPIKeyIds {
			var found bool
			for _, got := range got.Outputs["default"].ToRetireAPIKeyIds {
				found = found || cmp.Equal(want, got)
			}
			if !found {
				t.Errorf("could not find %#v, in %#v",
					want, got.Outputs["default"].ToRetireAPIKeyIds)
			}
		}

		// Assert deprecated fields
		assert.Nil(t, gotDeprecatedFields.DefaultAPIKey)
		assert.Nil(t, gotDeprecatedFields.DefaultAPIKeyID)
		assert.Nil(t, gotDeprecatedFields.PolicyOutputPermissionsHash)
		assert.Nil(t, gotDeprecatedFields.DefaultAPIKeyHistory)
	}
}

func TestMigrateOutputs_dontMigrateTwice(t *testing.T) {
	now, err := time.Parse(time.RFC3339, nowStr)
	require.NoError(t, err, "could not parse time "+nowStr)
	timeNow = func() time.Time {
		return now
	}

	index, bulker := ftesting.SetupCleanIndex(context.Background(), t, FleetAgents)
	apiKey := bulk.APIKey{
		ID:  "testAgent_",
		Key: "testAgent_key_",
	}

	agentIDs := createSomeAgents(t, 25, apiKey, index, bulker)

	migratedAgents, err := migrate(context.Background(), bulker, migrateAgentOutputs)
	require.NoError(t, err)
	assert.Equal(t, len(agentIDs), migratedAgents)

	migratedAgents2, err := migrate(context.Background(), bulker, migrateAgentOutputs)
	require.NoError(t, err)

	assert.Equal(t, 0, migratedAgents2)
}

func TestMigrateOutputs_nil_DefaultAPIKeyHistory(t *testing.T) {
	wantOutputType := "elasticsearch"

	now, err := time.Parse(time.RFC3339, nowStr)
	require.NoError(t, err, "could not parse time "+nowStr)
	timeNow = func() time.Time {
		return now
	}

	index, bulker := ftesting.SetupCleanIndex(context.Background(), t, FleetAgents)
	apiKey := bulk.APIKey{
		ID:  "testAgent_",
		Key: "testAgent_key_",
	}

	i := 0
	outputAPIKey := bulk.APIKey{
		ID:  fmt.Sprint(apiKey.ID, i),
		Key: fmt.Sprint(apiKey.Key, i),
	}

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
	}

	body, err := json.Marshal(agentModel)
	require.NoError(t, err)

	_, err = bulker.Create(
		context.Background(), index, agentID, body, bulk.WithRefresh())
	require.NoError(t, err)

	migratedAgents, err := migrate(context.Background(), bulker, migrateAgentOutputs)
	require.NoError(t, err)

	res, err := SearchWithOneParam(
		context.Background(), bulker, QueryAgentByID, index, FieldID, agentID)
	require.NoError(t, err, "failed to find agent ID %q", agentID)
	require.Len(t, res.Hits, 1)

	var got model.Agent
	err = res.Hits[0].Unmarshal(&got)
	require.NoError(t, err, "could not unmarshal ES document into model.Agent")

	gotDeprecatedFields := struct {
		// Deprecated. Use Outputs instead. API key the Elastic Agent uses to authenticate with elasticsearch
		DefaultAPIKey *string `json:"default_api_key,omitempty"`

		// Deprecated. Use Outputs instead. Default API Key History
		DefaultAPIKeyHistory []model.ToRetireAPIKeyIdsItems `json:"default_api_key_history,omitempty"`

		// Deprecated. Use Outputs instead. ID of the API key the Elastic Agent uses to authenticate with elasticsearch
		DefaultAPIKeyID *string `json:"default_api_key_id,omitempty"`

		// Deprecated. Use Outputs instead. The policy output permissions hash
		PolicyOutputPermissionsHash *string `json:"policy_output_permissions_hash,omitempty"`
	}{}
	err = res.Hits[0].Unmarshal(&gotDeprecatedFields)
	require.NoError(t, err, "could not unmarshal ES document into gotDeprecatedFields")

	assert.Equal(t, 1, migratedAgents)

	// Assert new fields
	require.Len(t, got.Outputs, 1)
	// Default API key is empty to force fleet-server to regenerate them.
	assert.Empty(t, got.Outputs["default"].APIKey)
	assert.Empty(t, got.Outputs["default"].APIKeyID)
	assert.Equal(t, wantOutputType, got.Outputs["default"].Type)
	assert.Equal(t,
		fmt.Sprint("a_output_permission_SHA_", i),
		got.Outputs["default"].PermissionsHash)

	// Assert ToRetireAPIKeyIds contains the expected values, regardless of the order.
	if assert.Len(t, got.Outputs["default"].ToRetireAPIKeyIds, 1) {
		assert.Equal(t,
			model.ToRetireAPIKeyIdsItems{ID: outputAPIKey.ID, RetiredAt: nowStr},
			got.Outputs["default"].ToRetireAPIKeyIds[0])
	}

	// Assert deprecated fields
	assert.Nil(t, gotDeprecatedFields.DefaultAPIKey)
	assert.Nil(t, gotDeprecatedFields.DefaultAPIKey)
	assert.Nil(t, gotDeprecatedFields.PolicyOutputPermissionsHash)
	assert.Nil(t, gotDeprecatedFields.DefaultAPIKeyHistory)
}

func TestMigrateOutputs_no_agent_document(t *testing.T) {
	now, err := time.Parse(time.RFC3339, nowStr)
	require.NoError(t, err, "could not parse time "+nowStr)
	timeNow = func() time.Time {
		return now
	}

	_, bulker := ftesting.SetupCleanIndex(context.Background(), t, FleetAgents)

	migratedAgents, err := migrate(context.Background(), bulker, migrateAgentOutputs)
	require.NoError(t, err)

	assert.Equal(t, 0, migratedAgents)
}
