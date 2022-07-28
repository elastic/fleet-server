//go:build integration

package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestRenderUpdatePainlessScript(t *testing.T) {
	tts := []struct {
		name string

		existingToRetireAPIKeys []model.ToRetireAPIKeysItems
	}{
		{
			name: "to_retire_api_keys is empty",
		},
		{
			name: "to_retire_api_keys is not empty",
			existingToRetireAPIKeys: []model.ToRetireAPIKeysItems{{
				ID: "pre_existing_ID", RetiredAt: "pre_existing__RetiredAt"}},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			outputPermissionSha := "new_permissionSHA_" + tt.name
			outputName := "output_" + tt.name
			outputAPIKey := bulk.APIKey{ID: "new_ID", Key: "new-key"}

			index, bulker := ftesting.SetupCleanIndex(context.Background(), t, dl.FleetAgents)

			now := time.Now().UTC()
			nowStr := now.Format(time.RFC3339)

			agentID := uuid.Must(uuid.NewV4()).String()
			policyID := uuid.Must(uuid.NewV4()).String()

			previousAPIKey := bulk.APIKey{
				ID:  "old_" + outputAPIKey.ID,
				Key: "old_" + outputAPIKey.Key,
			}

			wantElasticsearchOutputs := map[string]*model.PolicyOutput{
				outputName: {
					APIKey:                outputAPIKey.Agent(),
					APIKeyID:              outputAPIKey.ID,
					PolicyPermissionsHash: outputPermissionSha,
					ToRetireAPIKeys: append(tt.existingToRetireAPIKeys,
						model.ToRetireAPIKeysItems{
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
				ElasticsearchOutputs: map[string]*model.PolicyOutput{
					outputName: {
						APIKey:                previousAPIKey.Agent(),
						APIKeyID:              previousAPIKey.ID,
						PolicyPermissionsHash: "old_" + outputPermissionSha,
					},
				},
			}
			if tt.existingToRetireAPIKeys != nil {
				agentModel.ElasticsearchOutputs[outputName].ToRetireAPIKeys =
					tt.existingToRetireAPIKeys
			}

			body, err := json.Marshal(agentModel)
			require.NoError(t, err)

			_, err = bulker.Create(
				context.Background(), index, agentID, body, bulk.WithRefresh())
			require.NoError(t, err)

			fields := map[string]interface{}{
				dl.FieldPolicyOutputAPIKey:          outputAPIKey.Agent(),
				dl.FieldPolicyOutputAPIKeyID:        outputAPIKey.ID,
				dl.FieldPolicyOutputPermissionsHash: outputPermissionSha,
				dl.FieldPolicyOutputToRetireAPIKeys: model.ToRetireAPIKeysItems{
					ID: previousAPIKey.ID, RetiredAt: nowStr},
			}

			got, err := renderUpdatePainlessScript(outputName, fields)
			require.NoError(t, err, "renderUpdatePainlessScript returned an unexpected error")

			err = bulker.Update(context.Background(), dl.FleetAgents, agentID, got)
			require.NoError(t, err, "bulker.Update failed")

			// there is some refresh thing that needs time, I didn't manage to find
			// how ot fix it at the requests to ES level, thus this timeout here.
			time.Sleep(time.Second)

			gotAgent, err := dl.FindAgent(
				context.Background(), bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
			require.NoError(t, err)

			assert.Equal(t, agentID, gotAgent.Id)
			assert.Len(t, gotAgent.ElasticsearchOutputs, len(wantElasticsearchOutputs))
			assert.Equal(t, wantElasticsearchOutputs, gotAgent.ElasticsearchOutputs)
		})
	}
}
