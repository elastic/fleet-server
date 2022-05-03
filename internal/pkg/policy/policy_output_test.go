// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

var TestPayload []byte

func TestPolicyLogstashOutputPrepare(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	po := PolicyOutput{
		Type: OutputTypeLogstash,
		Name: "test output",
		Role: &RoleT{
			Sha2: "fake sha",
			Raw:  TestPayload,
		},
	}

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{})
	require.Nil(t, err, "expected prepare to pass")
	bulker.AssertExpectations(t)
}
func TestPolicyLogstashOutputPrepareNoRole(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	po := PolicyOutput{
		Type: OutputTypeLogstash,
		Name: "test output",
		Role: nil,
	}

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{})
	// No permissions are required by logstash currently
	require.Nil(t, err, "expected prepare to pass")
	bulker.AssertExpectations(t)
}

func TestPolicyDefaultLogstashOutputPrepare(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	po := PolicyOutput{
		Type: OutputTypeLogstash,
		Name: "test output",
		Role: &RoleT{
			Sha2: "fake sha",
			Raw:  TestPayload,
		},
	}

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{})
	require.Nil(t, err, "expected prepare to pass")
	bulker.AssertExpectations(t)
}

func TestPolicyESOutputPrepareNoRole(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	po := PolicyOutput{
		Type: OutputTypeElasticsearch,
		Name: "test output",
		Role: nil,
	}

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{})
	require.NotNil(t, err, "expected prepare to error")
	bulker.AssertExpectations(t)
}

func TestPolicyOutputESPrepare(t *testing.T) {
	t.Run("Permission hash == Agent Permission Hash no need to regenerate the key", func(t *testing.T) {
		bulker := ftesting.NewMockBulk()
		hashPerm := "abc123"
		po := PolicyOutput{
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
			DefaultAPIKey:               "test_id:EXISTING-KEY",
			PolicyOutputPermissionsHash: hashPerm,
		}

		err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap("test output")["api_key"].(string)

		require.True(t, ok, "unable to case api key")
		require.Equal(t, testAgent.DefaultAPIKey, key)
		bulker.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		bulker.AssertNotCalled(t, "ApiKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		bulker.AssertExpectations(t)
	})

	t.Run("Permission hash != Agent Permission Hash need to regenerate the key", func(t *testing.T) {
		bulker := ftesting.NewMockBulk()
		bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		bulker.On("ApiKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&bulk.APIKey{"abc", "new-key"}, nil).Once()

		po := PolicyOutput{
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
			DefaultAPIKey:               "test_id:EXISTING-KEY",
			PolicyOutputPermissionsHash: "old-HASH",
		}

		err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap("test output")["api_key"].(string)

		require.True(t, ok, "unable to case api key")
		require.Equal(t, "abc:new-key", key)
		bulker.AssertExpectations(t)
	})

	t.Run("Generate API Key on new Agent", func(t *testing.T) {
		bulker := ftesting.NewMockBulk()
		bulker.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		bulker.On("ApiKeyCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&bulk.APIKey{"abc", "new-key"}, nil).Once()

		po := PolicyOutput{
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

		testAgent := &model.Agent{}

		err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap("test output")["api_key"].(string)

		require.True(t, ok, "unable to case api key")
		require.Equal(t, "abc:new-key", key)
		bulker.AssertExpectations(t)
	})
}
