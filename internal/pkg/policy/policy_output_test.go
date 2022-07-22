// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, smap.Map{})
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, smap.Map{})
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, smap.Map{})
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

	err := po.Prepare(context.Background(), logger, bulker, &model.Agent{}, smap.Map{})
	require.NotNil(t, err, "expected prepare to error")
	bulker.AssertExpectations(t)
}

func TestPolicyOutputESPrepare_oldModel(t *testing.T) {
	// TODO: ensure the DefaultAPIKeyHistory is copied to ElasticsearchOutputs[].ToRetireAPIKeys
	// TODO: ensure current DefaultAPIKeyID id added to ElasticsearchOutputs[].ToRetireAPIKeys
	t.Run("Permission hash == Agent Permission Hash -> force generate the key", func(t *testing.T) {
		logger := testlog.SetLogger(t)

		apiKey := bulk.APIKey{ID: "test_id_existing", Key: "existing-key"}
		wantAPIKey := bulk.APIKey{ID: "test_id_new", Key: "new-key"}

		hashPerm := "abc123"
		output := Output{
			Type: OutputTypeElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: hashPerm,
				Raw:  TestPayload,
			},
		}

		bulker := ftesting.NewMockBulk()
		bulker.On("Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		bulker.On("APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&wantAPIKey, nil).Once() //nolint:govet // test case

		policyMap := smap.Map{
			"test output": map[string]interface{}{},
		}

		testAgent := &model.Agent{
			DefaultAPIKey:               apiKey.Agent(),
			PolicyOutputPermissionsHash: hashPerm,
			ElasticsearchOutputs:        map[string]*model.PolicyOutput{},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap(output.Name)["api_key"].(string)
		gotOutput := testAgent.ElasticsearchOutputs[output.Name]

		require.True(t, ok, "api key not present on policy map")
		assert.Equal(t, wantAPIKey.Agent(), key)

		// Migration path: copy old values to new ElasticsearchOutputs field
		assert.Equal(t, wantAPIKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, wantAPIKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PolicyPermissionsHash)

		// Migration path: ensure Default* fields are left empty
		assert.Empty(t, testAgent.DefaultAPIKey)
		assert.Empty(t, testAgent.DefaultAPIKeyID)
		assert.Empty(t, testAgent.DefaultAPIKeyHistory)
		assert.Empty(t, testAgent.PolicyOutputPermissionsHash)

		bulker.AssertExpectations(t)
	})

	t.Run("Permission hash != Agent Permission Hash need to regenerate the key", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()

		oldAPIKey := bulk.APIKey{ID: "test_id", Key: "EXISTING-KEY"}
		wantAPIKey := bulk.APIKey{ID: "abc", Key: "new-key"}
		hashPerm := "old-HASH"

		bulker.On("Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		bulker.On("APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&wantAPIKey, nil).Once() //nolint:govet // test case

		output := Output{
			Type: OutputTypeElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: "new-hash",
				Raw:  TestPayload,
			},
		}

		policyMap := smap.Map{
			"test output": map[string]interface{}{},
		}

		testAgent := &model.Agent{
			DefaultAPIKey:               oldAPIKey.Agent(),
			PolicyOutputPermissionsHash: hashPerm,
			ElasticsearchOutputs:        map[string]*model.PolicyOutput{
				// output.Name: {
				// 	ESDocument:            model.ESDocument{},
				// 	APIKey:                oldAPIKey.Agent(),
				// 	ToRetireAPIKeys:       nil,
				// 	APIKeyID:              oldAPIKey.ID,
				// 	PolicyPermissionsHash: hashPerm,
				// },
			},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap(output.Name)["api_key"].(string)
		gotOutput := testAgent.ElasticsearchOutputs[output.Name]

		require.True(t, ok, "unable to case api key")
		require.Equal(t, wantAPIKey.Agent(), key)

		// Migration path: copy old values to new ElasticsearchOutputs field
		assert.Equal(t, wantAPIKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, wantAPIKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PolicyPermissionsHash)

		// Migration path: ensure Default* fields are left empty
		assert.Empty(t, testAgent.DefaultAPIKey)
		assert.Empty(t, testAgent.DefaultAPIKeyID)
		assert.Empty(t, testAgent.DefaultAPIKeyHistory)
		assert.Empty(t, testAgent.PolicyOutputPermissionsHash)

		bulker.AssertExpectations(t)
	})
}

func TestPolicyOutputESPrepare_newModel(t *testing.T) {
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

		policyMap := smap.Map{
			"test output": map[string]interface{}{},
		}

		testAgent := &model.Agent{
			ElasticsearchOutputs: map[string]*model.PolicyOutput{
				output.Name: {
					ESDocument:            model.ESDocument{},
					APIKey:                apiKey.Agent(),
					ToRetireAPIKeys:       nil,
					APIKeyID:              apiKey.ID,
					PolicyPermissionsHash: hashPerm,
				},
			},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap(output.Name)["api_key"].(string)
		gotOutput := testAgent.ElasticsearchOutputs[output.Name]

		require.True(t, ok, "api key not present on policy map")
		assert.Equal(t, apiKey.Agent(), key)

		assert.Equal(t, apiKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, apiKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PolicyPermissionsHash)
		assert.Empty(t, gotOutput.ToRetireAPIKeys)

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

	t.Run("Permission hash != Agent Permission Hash need to regenerate the key", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		bulker := ftesting.NewMockBulk()

		oldAPIKey := bulk.APIKey{ID: "test_id", Key: "EXISTING-KEY"}
		wantAPIKey := bulk.APIKey{ID: "abc", Key: "new-key"}
		hashPerm := "old-HASH"

		bulker.On("Update",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		bulker.On("APIKeyCreate",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&wantAPIKey, nil).Once() //nolint:govet // test case

		output := Output{
			Type: OutputTypeElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: "new-hash",
				Raw:  TestPayload,
			},
		}

		policyMap := smap.Map{
			"test output": map[string]interface{}{},
		}

		testAgent := &model.Agent{
			ElasticsearchOutputs: map[string]*model.PolicyOutput{
				output.Name: {
					ESDocument:            model.ESDocument{},
					APIKey:                oldAPIKey.Agent(),
					ToRetireAPIKeys:       nil,
					APIKeyID:              oldAPIKey.ID,
					PolicyPermissionsHash: hashPerm,
				},
			},
		}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap(output.Name)["api_key"].(string)
		gotOutput := testAgent.ElasticsearchOutputs[output.Name]

		require.True(t, ok, "unable to case api key")
		require.Equal(t, wantAPIKey.Agent(), key)

		assert.Equal(t, wantAPIKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, wantAPIKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PolicyPermissionsHash)

		// assert.Contains(t, gotOutput.ToRetireAPIKeys, oldAPIKey.ID) // TODO: assert on bulker.Update

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
			Return(&apiKey, nil).Once() //nolint:govet // test case

		output := Output{
			Type: OutputTypeElasticsearch,
			Name: "test output",
			Role: &RoleT{
				Sha2: "new-hash",
				Raw:  TestPayload,
			},
		}

		policyMap := smap.Map{
			"test output": map[string]interface{}{},
		}

		testAgent := &model.Agent{ElasticsearchOutputs: map[string]*model.PolicyOutput{}}

		err := output.Prepare(context.Background(), logger, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap(output.Name)["api_key"].(string)
		gotOutput := testAgent.ElasticsearchOutputs[output.Name]

		require.True(t, ok, "unable to case api key")
		assert.Equal(t, apiKey.Agent(), key)

		assert.Equal(t, apiKey.Agent(), gotOutput.APIKey)
		assert.Equal(t, apiKey.ID, gotOutput.APIKeyID)
		assert.Equal(t, output.Role.Sha2, gotOutput.PolicyPermissionsHash)
		assert.Empty(t, gotOutput.ToRetireAPIKeys)

		// Old model must always remain empty
		assert.Empty(t, testAgent.DefaultAPIKey)
		assert.Empty(t, testAgent.DefaultAPIKeyID)
		assert.Empty(t, testAgent.DefaultAPIKeyHistory)
		assert.Empty(t, testAgent.PolicyOutputPermissionsHash)

		bulker.AssertExpectations(t)
	})
}

func TestRenderUpdatePainlessScript(t *testing.T) {

}
