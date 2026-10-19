// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

var TestPayload []byte

func TestRenderUpdatePainlessScriptParameterizesOutputName(t *testing.T) {
	const outputName = `output"';\()`
	fields := map[string]any{
		dl.FieldPolicyOutputAPIKeyID: "api-key-id",
	}

	body, err := renderUpdatePainlessScript(outputName, fields)
	require.NoError(t, err)

	var request struct {
		Script struct {
			Source string         `json:"source"`
			Params map[string]any `json:"params"`
		} `json:"script"`
	}
	require.NoError(t, json.Unmarshal(body, &request))

	assert.NotContains(t, request.Script.Source, outputName)
	assert.Contains(t, request.Script.Source, "params.output_name")
	assert.Equal(t, outputName, request.Script.Params["output_name"])
	assert.Equal(t, "api-key-id", request.Script.Params[dl.FieldPolicyOutputAPIKeyID])
	assert.NotContains(t, fields, "output_name")
}

func TestRenderRemoveOutputPainlessScriptParameterizesOutputName(t *testing.T) {
	const outputName = `output"';\()`

	body, err := renderRemoveOutputPainlessScript(outputName)
	require.NoError(t, err)

	var request struct {
		Script struct {
			Source string         `json:"source"`
			Params map[string]any `json:"params"`
		} `json:"script"`
	}
	require.NoError(t, json.Unmarshal(body, &request))

	assert.Equal(t, "ctx._source['outputs'].remove(params.output_name)", request.Script.Source)
	assert.NotContains(t, request.Script.Source, outputName)
	assert.Equal(t, outputName, request.Script.Params["output_name"])
}

type recordingOutputSecretCandidateCollector struct {
	candidates []OutputSecretCandidate
}

func (c *recordingOutputSecretCandidateCollector) Add(candidate OutputSecretCandidate) bool {
	c.candidates = append(c.candidates, candidate)
	return true
}

func TestPolicyLogstashOutputPrepare(t *testing.T) {
	logger := testlog.SetLogger(t)
	bulker := ftesting.NewMockBulk()
	po := Output{
		Type: OutputTypeLogstash,
		Name: "test output",
		Role: &RoleT{
			Sha2: "fake sha",
			Raw:  TestPayload,
		},
	}

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]any{})
	require.Nil(t, err, "expected prepare to pass")
	bulker.AssertExpectations(t)
}
func TestPolicyLogstashOutputPrepareNoRole(t *testing.T) {
	logger := testlog.SetLogger(t)
	bulker := ftesting.NewMockBulk()
	po := Output{
		Type: OutputTypeLogstash,
		Name: "test output",
		Role: nil,
	}

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]any{})
	// No permissions are required by logstash currently
	require.Nil(t, err, "expected prepare to pass")
	bulker.AssertExpectations(t)
}

func TestPolicyDefaultLogstashOutputPrepare(t *testing.T) {
	logger := testlog.SetLogger(t)
	bulker := ftesting.NewMockBulk()
	po := Output{
		Type: OutputTypeLogstash,
		Name: "test output",
		Role: &RoleT{
			Sha2: "fake sha",
			Raw:  TestPayload,
		},
	}

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]any{})
	require.Nil(t, err, "expected prepare to pass")
	bulker.AssertExpectations(t)
}

func TestPolicyKafkaOutputPrepare(t *testing.T) {
	logger := testlog.SetLogger(t)
	bulker := ftesting.NewMockBulk()
	po := Output{
		Type: OutputTypeKafka,
		Name: "test output",
		Role: &RoleT{
			Sha2: "fake sha",
			Raw:  TestPayload,
		},
	}

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]any{})
	require.Nil(t, err, "expected prepare to pass")
	bulker.AssertExpectations(t)
}
func TestPolicyKafkaOutputPrepareNoRole(t *testing.T) {
	logger := testlog.SetLogger(t)
	bulker := ftesting.NewMockBulk()
	po := Output{
		Type: OutputTypeKafka,
		Name: "test output",
		Role: nil,
	}

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]any{})
	// No permissions are required by kafka currently
	require.Nil(t, err, "expected prepare to pass")
	bulker.AssertExpectations(t)
}

func TestPolicyESOutputPrepareNoRole(t *testing.T) {
	logger := testlog.SetLogger(t)
	bulker := ftesting.NewMockBulk()
	po := Output{
		Type: OutputTypeElasticsearch,
		Name: "test output",
		Role: nil,
	}

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]any{})
	require.NotNil(t, err, "expected prepare to error")
	bulker.AssertExpectations(t)
}

func TestPolicyOutputESPrepare(t *testing.T) {
	t.Run("Permission hash == Agent Permission Hash no need to regenerate the key", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()

		apiKey := bulk.APIKey{ID: "test_id_existing", Key: "existing-key"}

		hashPerm := "abc123"
		output := Output{
			Type: OutputTypeElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: hashPerm,
				Raw:  TestPayload,
			},
		}

		policyMap := map[string]map[string]any{
			"test output": map[string]any{},
		}

		testAgent := &model.Agent{
			Outputs: map[string]*model.PolicyOutput{
				output.Name: {
					ESDocument:        model.ESDocument{},
					APIKey:            apiKey.Agent(),
					ToRetireAPIKeyIds: nil,
					APIKeyID:          apiKey.ID,
					PermissionsHash:   hashPerm,
					Type:              OutputTypeElasticsearch,
				},
			},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap[output.Name]["api_key"].(string)
		gotOutput := testAgent.Outputs[output.Name]

		require.True(t, ok, "api key not present on policy map")
		assert.Equal(t, apiKey.Agent(), key)

		assert.Equal(t, apiKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, apiKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PermissionsHash)
		assert.Equal(t, output.Type, gotOutput.Type)
		assert.Empty(t, gotOutput.ToRetireAPIKeyIds)

		// Old model must always remain empty
		assert.Empty(t, testAgent.DefaultAPIKey)
		assert.Empty(t, testAgent.DefaultAPIKeyID)
		assert.Empty(t, testAgent.DefaultAPIKeyHistory)
		assert.Empty(t, testAgent.PolicyOutputPermissionsHash)

		bulker.AssertNotCalled(t, "Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		bulker.AssertNotCalled(t, "APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		bulker.AssertExpectations(t)
	})

	t.Run("Permission hash != Agent Permission Hash need to regenerate permissions", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()

		oldAPIKey := bulk.APIKey{ID: "test_id", Key: "EXISTING-KEY"}
		wantAPIKey := bulk.APIKey{ID: "test_id", Key: "EXISTING-KEY"}
		hashPerm := "old-HASH"

		bulker.
			On("APIKeyRead", mock.Anything, mock.Anything, mock.Anything).
			Return(&bulk.APIKeyMetadata{ID: "test_id", RoleDescriptors: TestPayload}, nil).
			Once()
		bulker.On("Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		bulker.On("APIKeyUpdate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

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

		testAgent := &model.Agent{
			Outputs: map[string]*model.PolicyOutput{
				output.Name: {
					ESDocument:        model.ESDocument{},
					APIKey:            oldAPIKey.Agent(),
					ToRetireAPIKeyIds: nil,
					APIKeyID:          oldAPIKey.ID,
					PermissionsHash:   hashPerm,
					Type:              OutputTypeElasticsearch,
				},
			},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap[output.Name]["api_key"].(string)
		gotOutput := testAgent.Outputs[output.Name]

		require.True(t, ok, "unable to case api key")
		require.Equal(t, wantAPIKey.Agent(), key)

		assert.Equal(t, wantAPIKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, wantAPIKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PermissionsHash)
		assert.Equal(t, output.Type, gotOutput.Type)

		// assert.Contains(t, gotOutput.ToRetireAPIKeyIds, oldAPIKey.ID) // TODO: assert on bulker.Update

		// Old model must always remain empty
		assert.Empty(t, testAgent.DefaultAPIKey)
		assert.Empty(t, testAgent.DefaultAPIKeyID)
		assert.Empty(t, testAgent.DefaultAPIKeyHistory)
		assert.Empty(t, testAgent.PolicyOutputPermissionsHash)

		bulker.AssertExpectations(t)
	})

	t.Run("Generate API Key on new Agent", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()
		bulker.On("Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		apiKey := bulk.APIKey{ID: "abc", Key: "new-key"}
		bulker.On("APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&apiKey, nil).Once()
		const secretID = "test-secret-id"
		bulker.On("WriteSecret", mock.Anything, apiKey.Agent()).Return(secretID, nil).Once()

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

		testAgent := &model.Agent{Outputs: map[string]*model.PolicyOutput{}}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap[output.Name]["api_key"].(string)
		gotOutput := testAgent.Outputs[output.Name]

		// The policy map receives the resolved secret value, not the reference.
		require.True(t, ok, "unable to cast api key")
		assert.Equal(t, secretID+"_value", key)

		// The agent document stores the secret reference, not the plaintext key.
		assert.Equal(t, "$co.elastic.secret{"+secretID+"}", gotOutput.APIKey)
		assert.Equal(t, apiKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PermissionsHash)
		assert.Equal(t, output.Type, gotOutput.Type)
		assert.Empty(t, gotOutput.ToRetireAPIKeyIds)

		// Old model must always remain empty
		assert.Empty(t, testAgent.DefaultAPIKey)
		assert.Empty(t, testAgent.DefaultAPIKeyID)
		assert.Empty(t, testAgent.DefaultAPIKeyHistory)
		assert.Empty(t, testAgent.PolicyOutputPermissionsHash)

		bulker.AssertExpectations(t)
	})

	t.Run("Secret is retained when agent document update fails", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()
		apiKey := bulk.APIKey{ID: "abc", Key: "new-key"}
		bulker.On("APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&apiKey, nil).Once()
		const secretID = "test-secret-id"
		bulker.On("WriteSecret", mock.Anything, apiKey.Agent()).Return(secretID, nil).Once()
		bulker.On("Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("ES update failed")).Once()

		output := Output{
			Type: OutputTypeElasticsearch,
			Name: "test output",
			Role: &RoleT{Sha2: "new-hash", Raw: TestPayload},
		}
		policyMap := map[string]map[string]any{"test output": {}}
		testAgent := &model.Agent{ESDocument: model.ESDocument{Id: "agent-id"}, Outputs: map[string]*model.PolicyOutput{}}
		collector := &recordingOutputSecretCandidateCollector{}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap,
			WithOutputSecretCandidateCollector(collector))
		require.Error(t, err)
		bulker.AssertNotCalled(t, "DeleteSecret", mock.Anything, secretID)
		require.Equal(t, []OutputSecretCandidate{{
			AgentID:    "agent-id",
			OutputName: "test output",
			SecretID:   secretID,
			SecretRef:  "$co.elastic.secret{test-secret-id}",
		}}, collector.candidates)
		bulker.AssertExpectations(t)
	})

	t.Run("Existing plaintext key is delivered without modification", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()

		apiKey := bulk.APIKey{ID: "existing-id", Key: "existing-key"}
		hashPerm := "existing-hash"
		output := Output{
			Type: OutputTypeElasticsearch,
			Name: "test output",
			Role: &RoleT{Sha2: hashPerm, Raw: TestPayload},
		}
		policyMap := map[string]map[string]any{"test output": {}}
		testAgent := &model.Agent{
			Outputs: map[string]*model.PolicyOutput{
				output.Name: {
					APIKey:          apiKey.Agent(),
					APIKeyID:        apiKey.ID,
					PermissionsHash: hashPerm,
					Type:            OutputTypeElasticsearch,
				},
			},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err)

		// Plaintext key is passed through directly — WriteSecret is not called.
		key, ok := policyMap[output.Name]["api_key"].(string)
		require.True(t, ok)
		assert.Equal(t, apiKey.Agent(), key)
		bulker.AssertNotCalled(t, "WriteSecret", mock.Anything, mock.Anything)
		bulker.AssertExpectations(t)
	})
}

func TestPolicyOTLPOutputPrepareNoRole(t *testing.T) {
	logger := testlog.SetLogger(t)
	bulker := ftesting.NewMockBulk()
	po := Output{
		Type: OutputTypeOTLP,
		Name: "test output",
		Role: nil,
	}

	policyMap := map[string]map[string]any{
		"test output": {},
	}

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, policyMap)
	require.NoError(t, err, "external OTLP output with no role must not error")
	assert.Empty(t, policyMap["test output"]["api_key"], "outputMap must not be mutated")
	bulker.AssertExpectations(t)
}

func TestPolicyOTLPOutputPrepare(t *testing.T) {
	const (
		secretID = "test-secret-id"
		oldKeyID = "old-key-id"
	)
	secretRef := "$co.elastic.secret{" + secretID + "}"
	mintedKey := bulk.APIKey{ID: "new-key-id", Key: "new-key-secret"}

	tests := []struct {
		name           string
		roleHash       string
		existingOutput *model.PolicyOutput
		setupMocks     func(*ftesting.MockBulk)
		wantErr        bool
		wantAPIKey     string
		wantPermHash   string
		wantCandidates []OutputSecretCandidate
	}{
		{
			name:     "hash matches — resolves existing secret without minting",
			roleHash: "abc123",
			existingOutput: &model.PolicyOutput{
				APIKey:          secretRef,
				APIKeyID:        oldKeyID,
				PermissionsHash: "abc123",
			},
			setupMocks:   func(_ *ftesting.MockBulk) {},
			wantAPIKey:   secretID + "_value",
			wantPermHash: "abc123",
		},
		{
			name:     "hash changed — updates key permissions",
			roleHash: "new-hash",
			existingOutput: &model.PolicyOutput{
				APIKey:          secretRef,
				APIKeyID:        oldKeyID,
				PermissionsHash: "old-hash",
			},
			setupMocks: func(b *ftesting.MockBulk) {
				b.On("APIKeyRead", mock.Anything, oldKeyID).
					Return(&bulk.APIKeyMetadata{ID: oldKeyID, RoleDescriptors: TestPayload}, nil).Once()
				b.On("APIKeyUpdate", mock.Anything, oldKeyID).Return(nil).Once()
				b.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			},
			wantAPIKey:   secretID + "_value",
			wantPermHash: "new-hash",
		},
		{
			name:           "new agent — mints key and writes secret",
			roleHash:       "new-hash",
			existingOutput: nil,
			setupMocks: func(b *ftesting.MockBulk) {
				b.On("APIKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(&mintedKey, nil).Once()
				b.On("WriteSecret", mock.Anything, mintedKey.Agent()).Return(secretID, nil).Once()
				b.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			},
			wantAPIKey:   secretID + "_value",
			wantPermHash: "new-hash",
		},
		{
			name:           "agent doc update fails — secret candidate recorded",
			roleHash:       "new-hash",
			existingOutput: nil,
			setupMocks: func(b *ftesting.MockBulk) {
				b.On("APIKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(&mintedKey, nil).Once()
				b.On("WriteSecret", mock.Anything, mintedKey.Agent()).Return(secretID, nil).Once()
				b.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("ES update failed")).Once()
			},
			wantErr: true,
			wantCandidates: []OutputSecretCandidate{{
				AgentID:    "agent-id",
				OutputName: "test output",
				SecretID:   secretID,
				SecretRef:  secretRef,
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			bulker := ftesting.NewMockBulk()
			tc.setupMocks(bulker)

			outputs := map[string]*model.PolicyOutput{}
			if tc.existingOutput != nil {
				outputs["test output"] = tc.existingOutput
			}
			testAgent := &model.Agent{
				ESDocument: model.ESDocument{Id: "agent-id"},
				Outputs:    outputs,
			}
			output := Output{
				Type: OutputTypeOTLP,
				Name: "test output",
				Role: &RoleT{Sha2: tc.roleHash, Raw: TestPayload},
			}
			policyMap := map[string]map[string]any{"test output": {"type": OutputTypeOTLP}}
			collector := &recordingOutputSecretCandidateCollector{}

			err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap,
				WithOutputSecretCandidateCollector(collector))

			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantAPIKey, policyMap[output.Name]["api_key"])
				assert.Equal(t, tc.wantPermHash, testAgent.Outputs[output.Name].PermissionsHash)
			}
			assert.Equal(t, tc.wantCandidates, collector.candidates)
			bulker.AssertExpectations(t)
		})
	}
}

func TestPolicyOTLPOutputPrepareManagedToExternal(t *testing.T) {
	const (
		secretID = "prev-secret-id"
		oldKeyID = "prev-key-id"
	)
	secretRef := "$co.elastic.secret{" + secretID + "}"

	newAgent := func() *model.Agent {
		return &model.Agent{
			ESDocument: model.ESDocument{Id: "agent-id"},
			Outputs: map[string]*model.PolicyOutput{
				"test output": {
					Type:            OutputTypeOTLP,
					APIKey:          secretRef,
					APIKeyID:        oldKeyID,
					PermissionsHash: "old-hash",
				},
			},
		}
	}
	policyOutput := Output{
		Type: OutputTypeOTLP,
		Name: "test output",
		Role: nil, // no output_permissions → external OTLP
	}
	policyMap := map[string]map[string]any{"test output": {"type": OutputTypeOTLP}}

	t.Run("parks retirement record and clears active key fields", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()
		bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		agent := newAgent()
		err := policyOutput.Prepare(context.Background(), logger, bulker, agent, policyMap)
		require.NoError(t, err)
		assert.Empty(t, policyMap["test output"]["api_key"], "external OTLP must not inject an api_key")
		// Entry persists so the ack/checkin gate can retire the key.
		require.Contains(t, agent.Outputs, "test output", "output entry must be retained for deferred retirement")
		out := agent.Outputs["test output"]
		assert.Empty(t, out.APIKeyID, "active key id must be cleared")
		assert.Empty(t, out.APIKey, "active key secret must be cleared")
		assert.Empty(t, out.PermissionsHash, "permissions hash must be cleared")
		require.Len(t, out.ToRetireAPIKeyIds, 1, "one retirement record must be parked")
		assert.Equal(t, oldKeyID, out.ToRetireAPIKeyIds[0].ID)
		assert.Equal(t, secretID, out.ToRetireAPIKeyIds[0].SecretID)
		assert.Equal(t, OutputTypeOTLP, out.ToRetireAPIKeyIds[0].OutputType, "retirement record must carry the previous mOTLP type")
		bulker.AssertExpectations(t)
	})

	t.Run("retirement record carries previous type when prior output was not mOTLP", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()
		bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		agent := &model.Agent{
			ESDocument: model.ESDocument{Id: "agent-id"},
			Outputs: map[string]*model.PolicyOutput{
				"test output": {
					Type:            OutputTypeElasticsearch,
					APIKey:          secretRef,
					APIKeyID:        oldKeyID,
					PermissionsHash: "old-hash",
				},
			},
		}
		err := policyOutput.Prepare(context.Background(), logger, bulker, agent, policyMap)
		require.NoError(t, err)
		out := agent.Outputs["test output"]
		require.Len(t, out.ToRetireAPIKeyIds, 1)
		assert.Equal(t, OutputTypeElasticsearch, out.ToRetireAPIKeyIds[0].OutputType,
			"retirement record must carry the previous key type, not the new output type")
		bulker.AssertExpectations(t)
	})

	t.Run("no-op when no active key present", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()

		agent := &model.Agent{
			ESDocument: model.ESDocument{Id: "agent-id"},
			Outputs: map[string]*model.PolicyOutput{
				"test output": {
					Type:              OutputTypeOTLP,
					ToRetireAPIKeyIds: []model.ToRetireAPIKeyIdsItems{{ID: oldKeyID}},
				},
			},
		}
		err := policyOutput.Prepare(context.Background(), logger, bulker, agent, policyMap)
		require.NoError(t, err, "second call with cleared key must be a no-op")
		bulker.AssertNotCalled(t, "Update")
	})
}

func TestPolicyOTLPOutputPrepareRetiresRemovedOutput(t *testing.T) {
	const (
		removedOutputName  = "otlp-managed-removed"
		incomingOutputName = "otlp-external-incoming"

		removedKeyID    = "removed-output-key-id"
		removedSecretID = "removed-output-secret-id"
		pendingKeyID    = "pending-rotation-key-id"
		pendingSecretID = "pending-rotation-secret-id"
	)
	removedSecretRef := "$co.elastic.secret{" + removedSecretID + "}"

	// policyMap contains only the incoming external OTLP output.
	policyMap := map[string]map[string]any{
		incomingOutputName: {"type": OutputTypeOTLP},
	}
	// incomingOutput describes the new external OTLP output (Role == nil → no key management).
	incomingOutput := Output{
		Type: OutputTypeOTLP,
		Name: incomingOutputName,
		Role: nil,
	}

	// parseParkParams decodes an Update body and returns the script params map.
	parseParkParams := func(t *testing.T, body []byte) map[string]any {
		t.Helper()
		var req struct {
			Script struct {
				Params map[string]any `json:"params"`
			} `json:"script"`
		}
		require.NoError(t, json.Unmarshal(body, &req))
		return req.Script.Params
	}

	// isParkOnto returns a mock.MatchedBy matcher that accepts an Update body that parks a
	// retirement record onto the named incoming output.
	isParkOnto := func(incomingName string) any {
		return mock.MatchedBy(func(body []byte) bool {
			var req struct {
				Script struct {
					Params map[string]any `json:"params"`
				} `json:"script"`
			}
			if json.Unmarshal(body, &req) != nil {
				return false
			}
			return req.Script.Params["output_name"] == incomingName &&
				req.Script.Params[dl.FieldPolicyOutputToRetireAPIKeyIDs] != nil
		})
	}

	// isRemoveOf returns a mock.MatchedBy matcher that accepts an Update body that removes the
	// named output entry from the agent doc.
	isRemoveOf := func(outputName string) any {
		return mock.MatchedBy(func(body []byte) bool {
			var req struct {
				Script struct {
					Source string         `json:"source"`
					Params map[string]any `json:"params"`
				} `json:"script"`
			}
			if json.Unmarshal(body, &req) != nil {
				return false
			}
			return req.Script.Source == "ctx._source['outputs'].remove(params.output_name)" &&
				req.Script.Params["output_name"] == outputName
		})
	}

	tests := []struct {
		name           string
		pendingRecords []model.ToRetireAPIKeyIdsItems
		wantCalls      int
	}{
		{
			name:      "removed output has active key only",
			wantCalls: 2,
		},
		{
			name: "removed output has active key and pending rotation record",
			pendingRecords: []model.ToRetireAPIKeyIdsItems{
				{ID: pendingKeyID, SecretID: pendingSecretID, Output: removedOutputName, OutputType: OutputTypeOTLP},
			},
			wantCalls: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			bulker := ftesting.NewMockBulk()

			agent := &model.Agent{
				ESDocument: model.ESDocument{Id: "agent-id"},
				Outputs: map[string]*model.PolicyOutput{
					removedOutputName: {
						Type:              OutputTypeOTLP,
						APIKey:            removedSecretRef,
						APIKeyID:          removedKeyID,
						PermissionsHash:   "old-hash",
						ToRetireAPIKeyIds: tc.pendingRecords,
					},
				},
			}

			// Register expected Update calls in order. Park calls (onto the incoming output) must all
			// precede the remove call; NotBefore enforces the ordering.
			var prevCall *mock.Call
			for range tc.wantCalls - 1 {
				c := bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, isParkOnto(incomingOutputName), mock.Anything).
					Return(nil).Once()
				if prevCall != nil {
					c.NotBefore(prevCall)
				}
				prevCall = c
			}
			removeCall := bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, isRemoveOf(removedOutputName), mock.Anything).
				Return(nil).Once()
			if prevCall != nil {
				removeCall.NotBefore(prevCall)
			}

			err := incomingOutput.Prepare(context.Background(), logger, bulker, agent, policyMap)
			require.NoError(t, err)

			require.Len(t, bulker.Calls, tc.wantCalls)

			// If there were pending records, verify the first call transferred one of them.
			if len(tc.pendingRecords) > 0 {
				transferParams := parseParkParams(t, bulker.Calls[0].Arguments.Get(3).([]byte))
				transferRecord, ok := transferParams[dl.FieldPolicyOutputToRetireAPIKeyIDs].(map[string]any)
				require.True(t, ok, "first Update must be a transfer of the pending record")
				assert.Equal(t, pendingKeyID, transferRecord["id"])
			}

			// The second-to-last call parks the removed output's active key onto the incoming output.
			// Requirement (a): this call precedes the remove — enforced by NotBefore above.
			parkParams := parseParkParams(t, bulker.Calls[tc.wantCalls-2].Arguments.Get(3).([]byte))
			parkRecord, ok := parkParams[dl.FieldPolicyOutputToRetireAPIKeyIDs].(map[string]any)
			require.True(t, ok, "park body must contain a retirement record map")
			assert.Equal(t, removedKeyID, parkRecord["id"])
			assert.Equal(t, removedOutputName, parkRecord["output"])
			assert.Equal(t, OutputTypeOTLP, parkRecord["output_type"])
			assert.Equal(t, removedSecretID, parkRecord["secret_id"])
			assert.NotEmpty(t, parkRecord["retired_at"])

			// Requirement (b): the removed output is gone; the incoming output is present.
			assert.NotContains(t, agent.Outputs, removedOutputName, "removed output must be deleted from agent.Outputs")
			assert.Contains(t, agent.Outputs, incomingOutputName, "incoming output must be present in agent.Outputs")

			// External OTLP: no api_key injected into the policy map.
			assert.Empty(t, policyMap[incomingOutputName]["api_key"])

			bulker.AssertExpectations(t)
		})
	}
}

func TestPolicyRemoteESOutputPrepareNoRole(t *testing.T) {
	logger := testlog.SetLogger(t)
	bulker := ftesting.NewMockBulk()
	po := Output{
		Type: OutputTypeRemoteElasticsearch,
		Name: "test output",
		Role: nil,
	}
	outputBulker := ftesting.NewMockBulk()
	bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]any{})
	require.Error(t, err, "expected prepare to error")
	bulker.AssertExpectations(t)
}

func TestPolicyRemoteESOutputPrepare(t *testing.T) {
	t.Run("Permission hash == Agent Permission Hash no need to regenerate the key", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()

		apiKey := bulk.APIKey{ID: "test_id_existing", Key: "existing-key"}

		hashPerm := "abc123"
		output := Output{
			Type: OutputTypeRemoteElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: hashPerm,
				Raw:  TestPayload,
			},
		}

		outputBulker := ftesting.NewMockBulk()
		bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()

		policyMap := map[string]map[string]any{
			"test output": map[string]any{
				"hosts":         []any{"http://localhost"},
				"service_token": "serviceToken1",
				"type":          OutputTypeRemoteElasticsearch,
			},
		}

		testAgent := &model.Agent{
			Outputs: map[string]*model.PolicyOutput{
				output.Name: {
					ESDocument:        model.ESDocument{},
					APIKey:            apiKey.Agent(),
					ToRetireAPIKeyIds: nil,
					APIKeyID:          apiKey.ID,
					PermissionsHash:   hashPerm,
					Type:              OutputTypeRemoteElasticsearch,
				},
			},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap[output.Name]["api_key"].(string)
		gotOutput := testAgent.Outputs[output.Name]

		require.True(t, ok, "api key not present on policy map")
		assert.Equal(t, apiKey.Agent(), key)

		assert.Equal(t, apiKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, apiKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PermissionsHash)
		assert.Equal(t, output.Type, gotOutput.Type)
		assert.Empty(t, gotOutput.ToRetireAPIKeyIds)

		assert.Equal(t, OutputTypeElasticsearch, policyMap["test output"]["type"])
		assert.Empty(t, policyMap["test output"]["service_token"])

		bulker.AssertNotCalled(t, "Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		bulker.AssertNotCalled(t, "APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		bulker.AssertExpectations(t)
	})

	t.Run("Permission hash != Agent Permission Hash need to regenerate permissions", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()

		oldAPIKey := bulk.APIKey{ID: "test_id", Key: "EXISTING-KEY"}
		wantAPIKey := bulk.APIKey{ID: "test_id", Key: "EXISTING-KEY"}
		hashPerm := "old-HASH"

		bulker.On("Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()

		outputBulker := ftesting.NewMockBulk()
		bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()

		outputBulker.
			On("APIKeyRead", mock.Anything, mock.Anything, mock.Anything).
			Return(&bulk.APIKeyMetadata{ID: "test_id", RoleDescriptors: TestPayload}, nil).
			Once()
		outputBulker.On("APIKeyUpdate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		output := Output{
			Type: OutputTypeRemoteElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: "new-hash",
				Raw:  TestPayload,
			},
		}

		policyMap := map[string]map[string]any{
			"test output": map[string]any{
				"hosts":         []any{"http://localhost"},
				"service_token": "serviceToken1",
				"type":          OutputTypeRemoteElasticsearch,
			},
		}

		testAgent := &model.Agent{
			Outputs: map[string]*model.PolicyOutput{
				output.Name: {
					ESDocument:        model.ESDocument{},
					APIKey:            oldAPIKey.Agent(),
					ToRetireAPIKeyIds: nil,
					APIKeyID:          oldAPIKey.ID,
					PermissionsHash:   hashPerm,
					Type:              OutputTypeRemoteElasticsearch,
				},
			},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap[output.Name]["api_key"].(string)
		gotOutput := testAgent.Outputs[output.Name]

		require.True(t, ok, "unable to case api key")
		require.Equal(t, wantAPIKey.Agent(), key)

		assert.Equal(t, wantAPIKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, wantAPIKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PermissionsHash)
		assert.Equal(t, OutputTypeElasticsearch, gotOutput.Type) // remote_elasticsearch is normalized to elasticsearch on write

		assert.Equal(t, OutputTypeElasticsearch, policyMap["test output"]["type"])
		assert.Empty(t, policyMap["test output"]["service_token"])

		bulker.AssertExpectations(t)
	})

	t.Run("Generate API Key on new Agent", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()
		bulker.On("Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		apiKey := bulk.APIKey{ID: "abc", Key: "new-key"}

		outputBulker := ftesting.NewMockBulk()
		outputBulker.On("APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&apiKey, nil).Once()
		bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()
		bulker.On("Create", mock.Anything, dl.FleetOutputHealth, mock.Anything, mock.MatchedBy(func(body []byte) bool {
			var doc model.OutputHealth
			err := json.Unmarshal(body, &doc)
			if err != nil {
				t.Fatal(err)
			}
			return doc.Message == "" && doc.State == client.UnitStateHealthy.String()
		}), mock.Anything).Return("", nil)
		const secretID = "test-secret-id"
		bulker.On("WriteSecret", mock.Anything, apiKey.Agent()).Return(secretID, nil).Once()

		output := Output{
			Type: OutputTypeRemoteElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: "new-hash",
				Raw:  TestPayload,
			},
		}

		policyMap := map[string]map[string]any{
			"test output": map[string]any{
				"hosts":         []any{"http://localhost"},
				"service_token": "serviceToken1",
				"type":          OutputTypeRemoteElasticsearch,
			},
		}
		testAgent := &model.Agent{Outputs: map[string]*model.PolicyOutput{}}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap[output.Name]["api_key"].(string)
		gotOutput := testAgent.Outputs[output.Name]

		require.True(t, ok, "unable to cast api key")
		assert.Equal(t, secretID+"_value", key)

		assert.Equal(t, "$co.elastic.secret{"+secretID+"}", gotOutput.APIKey)
		assert.Equal(t, apiKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PermissionsHash)
		assert.Empty(t, gotOutput.ToRetireAPIKeyIds)

		assert.Equal(t, OutputTypeElasticsearch, policyMap["test output"]["type"])
		assert.Empty(t, policyMap["test output"]["service_token"])

		bulker.AssertExpectations(t)
	})

	t.Run("Report degraded output health on API key create failure", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()
		var apiKey *bulk.APIKey = nil
		var err error = errors.New("error connecting")

		outputBulker := ftesting.NewMockBulk()
		outputBulker.On("APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(apiKey, err).Once()
		bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()
		bulker.On("Create", mock.Anything, dl.FleetOutputHealth, mock.Anything, mock.MatchedBy(func(body []byte) bool {
			var doc model.OutputHealth
			err := json.Unmarshal(body, &doc)
			if err != nil {
				t.Fatal(err)
			}
			return doc.Message == "remote ES could not create API key due to error: error connecting" && doc.State == client.UnitStateDegraded.String()
		}), mock.Anything).Return("", nil)

		output := Output{
			Type: OutputTypeRemoteElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: "new-hash",
				Raw:  TestPayload,
			},
		}

		policyMap := map[string]map[string]any{
			"test output": map[string]any{
				"hosts":         []any{"http://localhost"},
				"service_token": "serviceToken1",
				"type":          OutputTypeRemoteElasticsearch,
			},
		}
		testAgent := &model.Agent{Outputs: map[string]*model.PolicyOutput{}}

		err = output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		bulker.AssertExpectations(t)
	})
}
