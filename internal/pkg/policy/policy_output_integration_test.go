// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/secret"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

// localPolicyESURL returns the local Elasticsearch URL with embedded credentials, suitable for
// ftesting.VerifyAPIKeyInvalidated. Reads ELASTICSEARCH_HOSTS or defaults to localhost:9200.
func localPolicyESURL() string {
	hosts := os.Getenv("ELASTICSEARCH_HOSTS")
	if hosts == "" {
		return "http://elastic:changeme@localhost:9200"
	}
	host := strings.SplitN(hosts, ",", 2)[0]
	return "http://elastic:changeme@" + host
}

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

			ctx := testlog.SetLogger(t).WithContext(t.Context())
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

			fields := map[string]any{
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

func TestRenderRemoveOutputPainlessScript(t *testing.T) {
	const outputName = `x"); ctx._source.pwned=("true`

	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)
	agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{
		outputName: {},
	})

	body, err := renderRemoveOutputPainlessScript(outputName)
	require.NoError(t, err)
	require.NoError(t, bulker.Update(ctx, dl.FleetAgents, agentID, body, bulk.WithRefresh()))

	agent, err := dl.FindAgent(
		ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	require.NoError(t, err)
	assert.Empty(t, agent.Outputs)
}

func TestPolicyOutputESPrepareRealES(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

	agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{})
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
	policyMap := map[string]map[string]any{
		"test output": map[string]any{},
	}

	err = output.prepareElasticsearch(
		ctx, zerolog.Nop(), bulker, bulker, &agent, policyMap, false, nil)
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
	require.True(t, ok, "no '%s' output found on agent document", output.Name)

	assert.Empty(t, gotOutput.ToRetireAPIKeyIds)
	assert.Equal(t, gotOutput.Type, OutputTypeElasticsearch)
	assert.Equal(t, gotOutput.PermissionsHash, output.Role.Sha2)
	assert.NotEmpty(t, gotOutput.APIKey)
	assert.NotEmpty(t, gotOutput.APIKeyID)
}

// mOTLPRole is the output_permissions role descriptor Kibana emits for a managed OTLP output.
var mOTLPRole = []byte(`{"_managed_otlp_apm":{"applications":[{"application":"apm","privileges":["event:write"],"resources":["*"]}]}}`)

func TestPolicyOutputOTLPPrepareRealES(t *testing.T) {
	const outputName = "test otlp"

	t.Run("mOTLP — mints scoped API key and writes secret ref to agent doc", func(t *testing.T) {
		ctx := testlog.SetLogger(t).WithContext(t.Context())
		index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

		agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{})
		agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		require.NoError(t, err)

		output := Output{
			Type: OutputTypeOTLP,
			Name: outputName,
			Role: &RoleT{Sha2: "new-hash", Raw: mOTLPRole},
		}
		policyMap := map[string]map[string]any{outputName: {}}

		require.NoError(t, output.prepareOTLP(ctx, zerolog.Nop(), bulker, &agent, policyMap, nil))

		resolvedAPIKey, _ := policyMap[outputName]["api_key"].(string)
		assert.NotEmpty(t, resolvedAPIKey, "resolved api_key must be written to outputMap")

		ftesting.Retry(t, ctx, func(ctx context.Context) error {
			got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
			if err != nil {
				return err
			}

			gotOutput, ok := got.Outputs[outputName]
			require.True(t, ok, "output %q not found on agent document", outputName)

			assert.Equal(t, OutputTypeOTLP, gotOutput.Type)
			assert.Equal(t, output.Role.Sha2, gotOutput.PermissionsHash)
			assert.NotEmpty(t, gotOutput.APIKeyID)

			_, isRef := secret.ParseSecretReference(gotOutput.APIKey)
			assert.True(t, isRef, "api_key on agent doc must be a secret reference, got %q", gotOutput.APIKey)

			return nil
		}, ftesting.RetrySleep(time.Second))
	})

	t.Run("output type change from elasticsearch to otlp updates persisted type", func(t *testing.T) {
		ctx := testlog.SetLogger(t).WithContext(t.Context())
		index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

		// Establish an elasticsearch output so the agent doc has Type:"elasticsearch",
		// a real APIKeyID, and hash "hash-v1".
		agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{})
		agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		require.NoError(t, err)

		esOut := Output{
			Type: OutputTypeElasticsearch,
			Name: outputName,
			Role: &RoleT{Sha2: "hash-v1", Raw: TestPayload},
		}
		require.NoError(t, esOut.prepareElasticsearch(ctx, zerolog.Nop(), bulker, bulker, &agent,
			map[string]map[string]any{outputName: {}}, false, nil))

		// Reload to capture the persisted elasticsearch key ID before the transition.
		var esKeyID string
		ftesting.Retry(t, ctx, func(ctx context.Context) error {
			got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
			if err != nil {
				return err
			}
			out, ok := got.Outputs[outputName]
			if !ok || out.APIKeyID == "" {
				return fmt.Errorf("elasticsearch output not yet persisted")
			}
			esKeyID = out.APIKeyID
			agent = got
			return nil
		}, ftesting.RetrySleep(time.Second))

		// Wait for the security index to refresh so the key is visible before the transition.
		ftesting.VerifyAPIKeyInvalidated(t, ctx, localPolicyESURL(), esKeyID, false)

		// Policy changes the output to OTLP with new permissions (hash "hash-v2").
		// The hash change triggers needUpdateKey → updateOutputAPIKeyRoles: same key,
		// updated roles, and persisted type updated to "otlp".
		otlpOut := Output{
			Type: OutputTypeOTLP,
			Name: outputName,
			Role: &RoleT{Sha2: "hash-v2", Raw: mOTLPRole},
		}
		require.NoError(t, otlpOut.prepareOTLP(ctx, zerolog.Nop(), bulker, &agent,
			map[string]map[string]any{outputName: {}}, nil))

		ftesting.Retry(t, ctx, func(ctx context.Context) error {
			got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
			if err != nil {
				return err
			}
			out, ok := got.Outputs[outputName]
			if !ok {
				return fmt.Errorf("output %q not found", outputName)
			}
			if out.Type != OutputTypeOTLP {
				return fmt.Errorf("type not yet updated: got %q, want %q", out.Type, OutputTypeOTLP)
			}
			return nil
		}, ftesting.RetrySleep(time.Second))

		got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		require.NoError(t, err)
		out := got.Outputs[outputName]
		require.NotNil(t, out)

		assert.Equal(t, OutputTypeOTLP, out.Type)
		assert.Equal(t, "hash-v2", out.PermissionsHash)
		assert.Equal(t, esKeyID, out.APIKeyID, "key must not rotate — only roles were updated")
		assert.Empty(t, out.ToRetireAPIKeyIds, "no key was retired — updateOutputAPIKeyRoles was called, not persistNewOutputAPIKey")
	})

	t.Run("external OTLP — no output_permissions, no API key minted", func(t *testing.T) {
		ctx := testlog.SetLogger(t).WithContext(t.Context())
		index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

		agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{})
		agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		require.NoError(t, err)

		output := Output{
			Type: OutputTypeOTLP,
			Name: outputName,
			Role: nil,
		}
		policyMap := map[string]map[string]any{outputName: {}}

		require.NoError(t, output.prepareOTLP(ctx, zerolog.Nop(), bulker, &agent, policyMap, nil))

		assert.Empty(t, policyMap[outputName]["api_key"], "external OTLP must not inject an api_key")

		got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		require.NoError(t, err)
		assert.Empty(t, got.Outputs, "agent doc must not be updated for external OTLP")
	})

	t.Run("mOTLP→external transition — retirement record parked, active key fields cleared", func(t *testing.T) {
		ctx := testlog.SetLogger(t).WithContext(t.Context())
		index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

		agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{})
		agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		require.NoError(t, err)

		// First: establish a managed OTLP output with a real API key and secret.
		mOTLPMap := map[string]map[string]any{outputName: {}}
		mOTLP := Output{Type: OutputTypeOTLP, Name: outputName, Role: &RoleT{Sha2: "hash-v1", Raw: mOTLPRole}}
		require.NoError(t, mOTLP.prepareOTLP(ctx, zerolog.Nop(), bulker, &agent, mOTLPMap, nil))

		oldKeyID := agent.Outputs[outputName].APIKeyID
		require.NotEmpty(t, oldKeyID, "expected an API key ID after mOTLP prepare")

		oldSecretRef := agent.Outputs[outputName].APIKey
		oldSecretID, ok := secret.ParseSecretReference(oldSecretRef)
		require.True(t, ok, "expected a secret reference after mOTLP prepare")

		// Wait for the security index to refresh so the key is visible before the transition.
		ftesting.VerifyAPIKeyInvalidated(t, ctx, localPolicyESURL(), oldKeyID, false)

		// Transition: policy removes output_permissions → external OTLP.
		// The retirement record is parked on the entry itself; invalidation is deferred to
		// the ack/checkin gate (updateAPIKey), consistent with how retireRemovedOutputs works.
		external := Output{Type: OutputTypeOTLP, Name: outputName, Role: nil}
		require.NoError(t, external.prepareOTLP(ctx, zerolog.Nop(), bulker, &agent, map[string]map[string]any{outputName: {}}, nil))

		// In-memory: entry retained with cleared active fields and retirement record parked.
		require.Contains(t, agent.Outputs, outputName, "entry must be retained for deferred retirement")
		out := agent.Outputs[outputName]
		assert.Empty(t, out.APIKeyID, "active key id must be cleared")
		assert.Empty(t, out.APIKey, "active key secret must be cleared")
		assert.Empty(t, out.PermissionsHash, "permissions hash must be cleared")
		require.Len(t, out.ToRetireAPIKeyIds, 1, "one retirement record must be parked")
		assert.Equal(t, oldKeyID, out.ToRetireAPIKeyIds[0].ID)
		assert.Equal(t, oldSecretID, out.ToRetireAPIKeyIds[0].SecretID)

		// Agent doc: entry persists with the retirement record and cleared active fields.
		got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		require.NoError(t, err)
		require.Contains(t, got.Outputs, outputName, "agent doc must still carry the entry")
		docOut := got.Outputs[outputName]
		assert.Empty(t, docOut.APIKeyID, "api_key_id must be cleared in agent doc")
		assert.Empty(t, docOut.APIKey, "api_key must be cleared in agent doc")
		assert.Equal(t, OutputTypeOTLP, docOut.Type, "type must be retained so ack/checkin gate routes to entry")
		require.Len(t, docOut.ToRetireAPIKeyIds, 1, "retirement record must be in agent doc")
		assert.Equal(t, oldKeyID, docOut.ToRetireAPIKeyIds[0].ID)
	})
}

func createAgent(ctx context.Context, t *testing.T, index string, bulker bulk.Bulk, outputs map[string]*model.PolicyOutput) string {
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
		Outputs:           outputs,
	}

	body, err := json.Marshal(agentModel)
	require.NoError(t, err)

	_, err = bulker.Create(
		ctx, index, agentID, body, bulk.WithRefresh())
	require.NoError(t, err)

	return agentID
}

func TestPolicyOutputESPrepareRemoteES(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

	agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{})
	agent, err := dl.FindAgent(
		ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	if err != nil {
		require.NoError(t, err, "failed to find agent ID %q", agentID)
	}

	output := Output{
		Type:         OutputTypeRemoteElasticsearch,
		Name:         "test remote output",
		ServiceToken: "token1",
		Role: &RoleT{
			Sha2: "new-hash",
			Raw:  TestPayload,
		},
	}
	policyMap := map[string]map[string]any{
		"test remote output": map[string]any{
			"hosts": []any{"http://localhost:9200"},
		},
	}

	err = output.prepareElasticsearch(
		ctx, zerolog.Nop(), bulker, bulker, &agent, policyMap, false, nil)
	require.NoError(t, err)

	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		got, err := dl.FindAgent(
			ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		if err != nil {
			require.NoError(t, err, "failed to find agent ID %q", agentID)
		}

		gotOutput, ok := got.Outputs[output.Name]
		require.True(t, ok, "no '%s' output found on agent document", output.Name)

		assert.Empty(t, gotOutput.ToRetireAPIKeyIds)
		assert.Equal(t, gotOutput.Type, OutputTypeElasticsearch)
		assert.Equal(t, gotOutput.PermissionsHash, output.Role.Sha2)
		assert.NotEmpty(t, gotOutput.APIKey)
		assert.NotEmpty(t, gotOutput.APIKeyID)
		return nil
	}, ftesting.RetrySleep(1*time.Second))
}

func TestPolicyOutputESPrepareESRetireRemoteAPIKeys(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

	// simulate a previous remote output, that is removed from outputMap
	agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{
		"remote output": &model.PolicyOutput{
			APIKey:   "apiKey1:value",
			APIKeyID: "apiKey1",
		},
	})
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
	policyMap := map[string]map[string]any{
		"test output": map[string]any{},
	}

	err = output.prepareElasticsearch(
		ctx, zerolog.Nop(), bulker, bulker, &agent, policyMap, false, nil)
	require.NoError(t, err)

	// Stale entry must be removed from the in-memory map immediately so that a second
	// surviving output's retireRemovedOutputs call does not re-park a duplicate record.
	assert.NotContains(t, agent.Outputs, "remote output", "stale entry must be removed from in-memory agent.Outputs")

	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		got, err := dl.FindAgent(
			ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		if err != nil {
			return err
		}
		gotOutput, ok := got.Outputs[output.Name]
		if !ok {
			return fmt.Errorf("output %q not yet on agent doc", output.Name)
		}
		if len(gotOutput.ToRetireAPIKeyIds) == 0 {
			return fmt.Errorf("ToRetireAPIKeyIds not yet populated on %q", output.Name)
		}
		return nil
	}, ftesting.RetrySleep(time.Second))

	got, err := dl.FindAgent(
		ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	require.NoError(t, err)

	gotOutput, ok := got.Outputs[output.Name]
	require.True(t, ok, "no '%s' output found on agent document", output.Name)

	assert.Equal(t, len(gotOutput.ToRetireAPIKeyIds), 1)
	assert.Equal(t, gotOutput.ToRetireAPIKeyIds[0].ID, "apiKey1")
	assert.Equal(t, gotOutput.ToRetireAPIKeyIds[0].Output, "remote output")
	assert.Equal(t, gotOutput.Type, OutputTypeElasticsearch)
	assert.Equal(t, gotOutput.PermissionsHash, output.Role.Sha2)
	assert.NotEmpty(t, gotOutput.APIKey)
	assert.NotEmpty(t, gotOutput.APIKeyID)
}

// TestPolicyOutputOTLPPrepareRetireRemovedOutput mirrors TestPolicyOutputESPrepareESRetireRemoteAPIKeys
// for the OTLP code path.  It seeds the agent with a real minted key (secret ref) on an "old otlp"
// output, then calls prepareOTLP for a different surviving output.  retireRemovedOutput must:
//   - write a retirement record onto the surviving output's ToRetireAPIKeyIds with the correct
//     ID, Output name, and SecretID (covers the secret.ParseSecretReference branch in retireRemovedOutput);
//   - remove the stale "old otlp" entry from the agent doc (the renderRemoveOutputPainlessScript
//     half, which TestPolicyOutputESPrepareESRetireRemoteAPIKeys leaves unverified).
func TestPolicyOutputOTLPPrepareRetireRemovedOutput(t *testing.T) {
	const (
		oldOutputName   = "old otlp"
		survivingOutput = "surviving otlp"
	)

	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

	// Phase 1: mint a real OTLP key and secret for "old otlp" by running prepareOTLP.
	agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{})
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	require.NoError(t, err)

	setupOutput := Output{Type: OutputTypeOTLP, Name: oldOutputName, Role: &RoleT{Sha2: "hash-v1", Raw: mOTLPRole}}
	require.NoError(t, setupOutput.prepareOTLP(ctx, zerolog.Nop(), bulker, &agent, map[string]map[string]any{oldOutputName: {}}, nil))

	oldKeyID := agent.Outputs[oldOutputName].APIKeyID
	require.NotEmpty(t, oldKeyID, "setup: expected APIKeyID after mOTLP prepare")

	oldSecretID, ok := secret.ParseSecretReference(agent.Outputs[oldOutputName].APIKey)
	require.True(t, ok, "setup: expected secret reference after mOTLP prepare")

	// Phase 2: prepareOTLP for the surviving output; outputMap no longer contains "old otlp".
	// retireRemovedOutput scans agent.Outputs, finds "old otlp" absent from outputMap, and writes
	// a retirement record onto "surviving otlp", then removes the stale entry.
	survivingOutputObj := Output{
		Type: OutputTypeOTLP,
		Name: survivingOutput,
		Role: &RoleT{Sha2: "hash-v1", Raw: mOTLPRole},
	}
	outputMap := map[string]map[string]any{survivingOutput: {}}
	require.NoError(t, survivingOutputObj.prepareOTLP(ctx, zerolog.Nop(), bulker, &agent, outputMap, nil))

	// Stale entry must be removed from the in-memory map immediately.
	assert.NotContains(t, agent.Outputs, oldOutputName, "stale entry must be removed from in-memory agent.Outputs")

	// Wait for both painless updates (retire record + remove stale entry) to be visible.
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		if err != nil {
			return err
		}
		sv, ok := got.Outputs[survivingOutput]
		if !ok {
			return fmt.Errorf("output %q not yet on agent doc", survivingOutput)
		}
		if len(sv.ToRetireAPIKeyIds) == 0 {
			return fmt.Errorf("ToRetireAPIKeyIds not yet populated on %q", survivingOutput)
		}
		if _, stillPresent := got.Outputs[oldOutputName]; stillPresent {
			return fmt.Errorf("stale output %q still on agent doc", oldOutputName)
		}
		return nil
	}, ftesting.RetrySleep(time.Second))

	got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	require.NoError(t, err)

	// Surviving output must carry the retirement record for "old otlp".
	sv, ok := got.Outputs[survivingOutput]
	require.True(t, ok, "surviving output %q must be present", survivingOutput)
	require.Len(t, sv.ToRetireAPIKeyIds, 1, "exactly one retirement record expected")
	assert.Equal(t, oldKeyID, sv.ToRetireAPIKeyIds[0].ID, "retired key ID")
	assert.Equal(t, oldOutputName, sv.ToRetireAPIKeyIds[0].Output, "retired key output name")
	assert.Equal(t, oldSecretID, sv.ToRetireAPIKeyIds[0].SecretID, "retired key secret ID")
	assert.NotEmpty(t, sv.ToRetireAPIKeyIds[0].RetiredAt, "RetiredAt must be set")
	assert.Equal(t, OutputTypeOTLP, sv.Type, "surviving output type")
	assert.NotEmpty(t, sv.APIKeyID, "surviving output must have a fresh key")

	// The stale "old otlp" entry must be gone — this is the half TestPolicyOutputESPrepareESRetireRemoteAPIKeys
	// leaves unverified.
	assert.NotContains(t, got.Outputs, oldOutputName, "stale output entry must be removed from agent doc")
}

// TestPolicyOutputRetireMultipleRemovedOutputs verifies that retireRemovedOutputs processes
// all removed outputs in a single call. This matters when multiple integration-specific outputs
// are removed from a policy in one revision but only one surviving output calls Prepare.
func TestPolicyOutputRetireMultipleRemovedOutputs(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

	// Seed agent with two stale outputs (both absent from the new policy).
	agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{
		"removed-a": {APIKey: "key-a:val", APIKeyID: "key-a"},
		"removed-b": {APIKey: "key-b:val", APIKeyID: "key-b"},
	})
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	require.NoError(t, err)

	survivor := Output{
		Type: OutputTypeElasticsearch,
		Name: "survivor",
		Role: &RoleT{Sha2: "hash-v1", Raw: TestPayload},
	}
	outputMap := map[string]map[string]any{"survivor": {}}

	require.NoError(t, survivor.prepareElasticsearch(ctx, zerolog.Nop(), bulker, bulker, &agent, outputMap, false, nil))

	// Both stale entries must be gone from the in-memory map immediately.
	assert.NotContains(t, agent.Outputs, "removed-a", "removed-a must be removed from in-memory agent.Outputs")
	assert.NotContains(t, agent.Outputs, "removed-b", "removed-b must be removed from in-memory agent.Outputs")

	// Both retirement records must appear on the survivor in the persisted doc.
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		if err != nil {
			return err
		}
		sv, ok := got.Outputs["survivor"]
		if !ok {
			return fmt.Errorf("survivor output not yet on agent doc")
		}
		if len(sv.ToRetireAPIKeyIds) < 2 {
			return fmt.Errorf("expected 2 retirement records, got %d", len(sv.ToRetireAPIKeyIds))
		}
		return nil
	}, ftesting.RetrySleep(time.Second))

	got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	require.NoError(t, err)

	sv, ok := got.Outputs["survivor"]
	require.True(t, ok)
	require.Len(t, sv.ToRetireAPIKeyIds, 2)

	retiredIDs := []string{sv.ToRetireAPIKeyIds[0].ID, sv.ToRetireAPIKeyIds[1].ID}
	assert.ElementsMatch(t, []string{"key-a", "key-b"}, retiredIDs)

	assert.NotContains(t, got.Outputs, "removed-a", "removed-a must be absent from persisted doc")
	assert.NotContains(t, got.Outputs, "removed-b", "removed-b must be absent from persisted doc")
}

// TestPolicyOutputRetireNoDuplicateAcrossSurvivors verifies that when two outputs survive a
// policy revision and each calls retireRemovedOutputs, the single removed output produces exactly
// one retirement record — not one per surviving output. The in-memory delete in retireRemovedOutputs
// is what prevents the duplicate.
func TestPolicyOutputRetireNoDuplicateAcrossSurvivors(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)

	// Seed agent with one stale output.
	agentID := createAgent(ctx, t, index, bulker, map[string]*model.PolicyOutput{
		"removed": {APIKey: "key-r:val", APIKeyID: "key-r"},
	})
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	require.NoError(t, err)

	// Two surviving outputs: one ES, one OTLP. Both call retireRemovedOutputs.
	outputMap := map[string]map[string]any{
		"es-out":   {},
		"otlp-out": {},
	}

	esOut := Output{Type: OutputTypeElasticsearch, Name: "es-out", Role: &RoleT{Sha2: "hash-v1", Raw: TestPayload}}
	require.NoError(t, esOut.prepareElasticsearch(ctx, zerolog.Nop(), bulker, bulker, &agent, outputMap, false, nil))

	otlpOut := Output{Type: OutputTypeOTLP, Name: "otlp-out", Role: &RoleT{Sha2: "hash-v1", Raw: mOTLPRole}}
	require.NoError(t, otlpOut.prepareOTLP(ctx, zerolog.Nop(), bulker, &agent, outputMap, nil))

	// Wait for all updates to be visible.
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
		if err != nil {
			return err
		}
		if _, stillPresent := got.Outputs["removed"]; stillPresent {
			return fmt.Errorf("stale output still present on agent doc")
		}
		return nil
	}, ftesting.RetrySleep(time.Second))

	got, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID, dl.WithIndexName(index))
	require.NoError(t, err)

	// Count total retirement records across all surviving outputs. Must be exactly 1.
	var totalRetirements int
	for _, out := range got.Outputs {
		totalRetirements += len(out.ToRetireAPIKeyIds)
	}
	assert.Equal(t, 1, totalRetirements, "exactly one retirement record expected across all surviving outputs; got %d (duplicate records indicate the in-memory delete is not working)", totalRetirements)

	assert.NotContains(t, got.Outputs, "removed")
}
