// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

var TestPayload []byte

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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]interface{}{})
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]interface{}{})
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]interface{}{})
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]interface{}{})
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]interface{}{})
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]interface{}{})
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

		policyMap := map[string]map[string]interface{}{
			"test output": map[string]interface{}{},
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

		policyMap := map[string]map[string]interface{}{
			"test output": map[string]interface{}{},
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

		testAgent := &model.Agent{Outputs: map[string]*model.PolicyOutput{}}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap[output.Name]["api_key"].(string)
		gotOutput := testAgent.Outputs[output.Name]

		require.True(t, ok, "unable to case api key")
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

		bulker.AssertExpectations(t)
	})
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
	bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, map[string]map[string]interface{}{})
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
		bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()

		policyMap := map[string]map[string]interface{}{
			"test output": map[string]interface{}{
				"hosts":         []interface{}{"http://localhost"},
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
		bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()

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

		policyMap := map[string]map[string]interface{}{
			"test output": map[string]interface{}{
				"hosts":         []interface{}{"http://localhost"},
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
		assert.Equal(t, output.Type, gotOutput.Type)

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
		bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(outputBulker, false).Once()

		output := Output{
			Type: OutputTypeRemoteElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: "new-hash",
				Raw:  TestPayload,
			},
		}

		policyMap := map[string]map[string]interface{}{
			"test output": map[string]interface{}{
				"hosts":         []interface{}{"http://localhost"},
				"service_token": "serviceToken1",
				"type":          OutputTypeRemoteElasticsearch,
			},
		}
		testAgent := &model.Agent{Outputs: map[string]*model.PolicyOutput{}}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap[output.Name]["api_key"].(string)
		gotOutput := testAgent.Outputs[output.Name]

		require.True(t, ok, "unable to case api key")
		assert.Equal(t, apiKey.Agent(), key)

		assert.Equal(t, apiKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, apiKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PermissionsHash)
		assert.Empty(t, gotOutput.ToRetireAPIKeyIds)

		assert.Equal(t, OutputTypeElasticsearch, policyMap["test output"]["type"])
		assert.Empty(t, policyMap["test output"]["service_token"])

		bulker.AssertExpectations(t)
	})
}
