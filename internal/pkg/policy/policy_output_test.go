// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
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

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{}, false)
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

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{}, false)
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

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{}, true)
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

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, smap.Map{}, false)
	require.NotNil(t, err, "expected prepare to error")
}

func TestPolicyOutputESPrepare(t *testing.T) {
	bulker := ftesting.NewMockBulk(&bulk.ApiKey{
		Id:  "test id",
		Key: "test key",
	})
	po := PolicyOutput{
		Type: OutputTypeElasticsearch,
		Name: "test output",
		Role: &RoleT{
			Sha2: "fake sha",
			Raw:  TestPayload,
		},
	}
	policyMap := smap.Map{
		"test output": map[string]interface{}{
			"api_key": "",
		},
	}

	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, &model.Agent{}, policyMap, false)
	require.Nil(t, err, "expected prepare to pass")

	updatedKey, ok := policyMap.GetMap("test output")["api_key"].(string)

	require.True(t, ok, "unable to case api key")
	require.Equal(t, updatedKey, bulker.MockedAPIKey.Agent())
	require.Equal(t, len(bulker.ArgumentData.Update), 0, "update should not be called")
}

func TestPolicyOutputDefaultESPrepare(t *testing.T) {
	bulker := ftesting.NewMockBulk(&bulk.ApiKey{
		Id:  "test id",
		Key: "test key",
	})
	po := PolicyOutput{
		Type: OutputTypeElasticsearch,
		Name: "test output",
		Role: &RoleT{
			Sha2: "fake sha",
			Raw:  TestPayload,
		},
	}
	policyMap := smap.Map{
		"test output": map[string]interface{}{},
	}
	testAgent := &model.Agent{}
	err := po.Prepare(context.Background(), zerolog.Logger{}, bulker, testAgent, policyMap, true)
	require.Nil(t, err, "expected prepare to pass")

	updatedKey, ok := policyMap.GetMap("test output")["api_key"].(string)

	require.True(t, ok, "unable to case api key")
	require.Equal(t, updatedKey, bulker.MockedAPIKey.Agent())
	require.Greater(t, len(bulker.ArgumentData.Update), 0, "update should be called")
}
