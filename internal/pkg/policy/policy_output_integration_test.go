// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

var TestPayload []byte

func TestRenderUpdatePainlessScript(t *testing.T) {
	tts := []struct {
		name string

		existingToRetireAPIKeyIds []model.ToRetireAPIKeyIdsItems
	}{
		{
			name: "to_retire_api_key_ids is empty",
		},
		{
			name: "to_retire_api_key_ids is not empty",
			existingToRetireAPIKeyIds: []model.ToRetireAPIKeyIdsItems{{
				ID: "pre_existing_ID", RetiredAt: "pre_existing__RetiredAt"}},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			outputPermissionSha := "new_permissionSHA_" + tt.name
			outputName := "output_" + tt.name
			outputAPIKey := bulk.APIKey{ID: "new_ID", Key: "new-key"}

			ctx := testlog.SetLogger(t).WithContext(context.Background())
			index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

			now := time.Now().UTC()
			nowStr := now.Format(time.RFC3339)

			agentID := uuid.Must(uuid.NewV4()).String()
			policyID := uuid.Must(uuid.NewV4()).String()

			previousAPIKey := bulk.APIKey{
				ID:  "old_" + outputAPIKey.ID,
				Key: "old_" + outputAPIKey.Key,
			}

			wantOutputs := map[string]*model.PolicyOutput{
				outputName: {
					APIKey:          outputAPIKey.Agent(),
					APIKeyID:        outputAPIKey.ID,
					PermissionsHash: outputPermissionSha,
					Type:            OutputTypeElasticsearch,
					ToRetireAPIKeyIds: append(tt.existingToRetireAPIKeyIds,
						model.ToRetireAPIKeyIdsItems{
							ID: previousAPIKey.ID, RetiredAt: nowStr}),
				},
			}

			agentModel := model.Agent{
				PolicyID:          policyID,
				Active:            true,
				LastCheckin:       nowStr,
				LastCheckinStatus: "",
				UpdatedAt:         nowStr,
				EnrolledAt:        nowStr,
				Outputs: map[string]*model.PolicyOutput{
					outputName: {
						Type:            OutputTypeElasticsearch,
						APIKey:          previousAPIKey.Agent(),
						APIKeyID:        previousAPIKey.ID,
						PermissionsHash: "old_" + outputPermissionSha,
					},
				},
			}
			if tt.existingToRetireAPIKeyIds != nil {
				agentModel.Outputs[outputName].ToRetireAPIKeyIds =
					tt.existingToRetireAPIKeyIds
			}

			body, err := json.Marshal(agentModel)
			require.NoError(t, err)

			_, err = bulker.Create(
				ctx, index, agentID, body, bulk.WithRefresh())
			require.NoError(t, err)

			fields := map[string]interface{}{
				dl.FieldPolicyOutputAPIKey:          outputAPIKey.Agent(),
				dl.FieldPolicyOutputAPIKeyID:        outputAPIKey.ID,
				dl.FieldPolicyOutputPermissionsHash: outputPermissionSha,
				dl.FieldPolicyOutputToRetireAPIKeyIDs: model.ToRetireAPIKeyIdsItems{
					ID: previousAPIKey.ID, RetiredAt: nowStr},
			}

			got, err := renderUpdatePainlessScript(outputName, fields)
			require.NoError(t, err, "renderUpdatePainlessScript returned an unexpected error")

			err = bulker.Update(ctx, dl.FleetAgents, agentID, got)
			require.NoError(t, err, "bulker.Update failed")

			// there is some refresh thing that needs time, I didn't manage to find
			// how ot fix it at the requests to ES level, thus this timeout here.
			time.Sleep(time.Second)

			gotAgent, err := dl.FindAgent(
				ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
			require.NoError(t, err)

			assert.Equal(t, agentID, gotAgent.Id)
			assert.Len(t, gotAgent.Outputs, len(wantOutputs))
			assert.Equal(t, wantOutputs, gotAgent.Outputs)
		})
	}
}

func TestPolicyOutputESPrepareRealES(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(context.Background())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

	agentID := createAgent(ctx, t, index, bulker)
	agent, err := dl.FindAgent(
		ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	if err != nil {
		require.NoError(t, err, "failed to find agent ID %q", agentID)
	}

	output := Output{
		Type: OutputTypeElasticsearch,
		Name: "test output",
		Role: &RoleT{
			Sha2: "new-hash",
			Raw:  TestPayload,
		},
	}
	policyMap := map[string]map[string]interface{}{
		"test output": map[string]interface{}{},
	}

	err = output.prepareElasticsearch(
		ctx, zerolog.Nop(), bulker, bulker, &agent, policyMap, false)
	require.NoError(t, err)

	// need to wait a bit before querying the agent again
	// TODO: find a better way to query the updated agent
	time.Sleep(time.Second)

	got, err := dl.FindAgent(
		ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	if err != nil {
		require.NoError(t, err, "failed to find agent ID %q", agentID)
	}

	gotOutput, ok := got.Outputs[output.Name]
	require.True(t, ok, "no '%s' output fouled on agent document", output.Name)

	assert.Empty(t, gotOutput.ToRetireAPIKeyIds)
	assert.Equal(t, gotOutput.Type, OutputTypeElasticsearch)
	assert.Equal(t, gotOutput.PermissionsHash, output.Role.Sha2)
	assert.NotEmpty(t, gotOutput.APIKey)
	assert.NotEmpty(t, gotOutput.APIKeyID)
}

func createAgent(ctx context.Context, t *testing.T, index string, bulker bulk.Bulk) string {
	const nowStr = "2022-08-12T16:50:05Z"

	agentID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()

	agentModel := model.Agent{
		PolicyID:          policyID,
		Active:            true,
		LastCheckin:       nowStr,
		LastCheckinStatus: "",
		UpdatedAt:         nowStr,
		EnrolledAt:        nowStr,
	}

	body, err := json.Marshal(agentModel)
	require.NoError(t, err)

	_, err = bulker.Create(
		ctx, index, agentID, body, bulk.WithRefresh())
	require.NoError(t, err)

	return agentID
}
