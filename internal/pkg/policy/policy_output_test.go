// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

var TestPayload []byte

func TestPolicyLogstashOutputPrepare(t *testing.T) {
	bulker := ftesting.NewMockBulk(&bulk.ApiKey{
		Id:  "test id",
		Key: "test key",
	})
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
}
func TestPolicyLogstashOutputPrepareNoRole(t *testing.T) {
	bulker := ftesting.NewMockBulk(&bulk.ApiKey{
		Id:  "test id",
		Key: "test key",
	})
	po := PolicyOutput{
		Type: OutputTypeLogstash,
		Name: "test output",
		Role: nil,
	}

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{})
	// No permissions are required by logstash currently
	require.Nil(t, err, "expected prepare to pass")
}

func TestPolicyDefaultLogstashOutputPrepare(t *testing.T) {
	bulker := ftesting.NewMockBulk(&bulk.ApiKey{
		Id:  "test id",
		Key: "test key",
	})
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
}

func TestPolicyESOutputPrepareNoRole(t *testing.T) {
	bulker := ftesting.NewMockBulk(&bulk.ApiKey{
		Id:  "test id",
		Key: "test key",
	})
	po := PolicyOutput{
		Type: OutputTypeElasticsearch,
		Name: "test output",
		Role: nil,
	}

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{})
	require.NotNil(t, err, "expected prepare to error")
}

func TestPolicyOutputESPrepare(t *testing.T) {
	t.Run("Permission hash == Agent Permission Hash no need to regenerate the key", func(t *testing.T) {
		bulker := ftesting.NewMockBulk(&bulk.ApiKey{})
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
			DefaultApiKey:               "test_id:EXISTING-KEY",
			PolicyOutputPermissionsHash: hashPerm,
		}

		err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap("test output")["api_key"].(string)

		require.True(t, ok, "unable to case api key")
		require.Equal(t, testAgent.DefaultApiKey, key)
		require.Equal(t, len(bulker.ArgumentData.Update), 0, "update should not be called")
	})

	t.Run("Permission hash != Agent Permission Hash need to regenerate the key", func(t *testing.T) {
		bulker := ftesting.NewMockBulk(&bulk.ApiKey{
			Id:  "abc",
			Key: "new-key",
		})

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
			DefaultApiKey:               "test_id:EXISTING-KEY",
			PolicyOutputPermissionsHash: "old-HASH",
		}

		err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, testAgent, policyMap)
		require.NoError(t, err, "expected prepare to pass")

		key, ok := policyMap.GetMap("test output")["api_key"].(string)

		require.True(t, ok, "unable to case api key")
		require.Equal(t, "abc:new-key", key)
		require.Equal(t, len(bulker.ArgumentData.Update), 1, "update should be called")
	})

	t.Run("Generate API Key on new Agent", func(t *testing.T) {
		bulker := ftesting.NewMockBulk(&bulk.ApiKey{
			Id:  "abc",
			Key: "new-key",
		})

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
		require.Equal(t, len(bulker.ArgumentData.Update), 1, "update should be called")
	})
}
