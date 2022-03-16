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
	if err != nil {
		t.Error("expected prepare to pass")
	}
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
	if err != nil {
		t.Error("expected prepare to pass")
	}
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
	if err != nil {
		t.Error("expected prepare to pass")
	}
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
	if err == nil {
		t.Error("expected error to be raised")
	}
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
	if err != nil {
		t.Error("expected prepare to pass", err)
	}

	updatedKey := policyMap.GetMap("test output")["api_key"].(*bulk.ApiKey)
	if updatedKey.Key != bulker.MockedAPIKey.Key {
		t.Errorf("api key should be updated. wanted: %s, got: %s", bulker.MockedAPIKey.Key, updatedKey.Key)
	}
	if updatedKey.Id != bulker.MockedAPIKey.Id {
		t.Errorf("api key ID should be updated. wanted: %s, got: %s", bulker.MockedAPIKey.Id, updatedKey.Id)
	}

	if len(bulker.ArgumentData.Update) > 0 {
		t.Error("update should not be called")
	}
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
	if err != nil {
		t.Error("expected prepare to pass", err)
	}

	updatedKey := policyMap.GetMap("test output")["api_key"].(*bulk.ApiKey)
	if updatedKey.Key != bulker.MockedAPIKey.Key {
		t.Errorf("api key should be updated. wanted: %s, got: %s", bulker.MockedAPIKey.Key, updatedKey.Key)
	}
	if updatedKey.Id != bulker.MockedAPIKey.Id {
		t.Errorf("api key ID should be updated. wanted: %s, got: %s", bulker.MockedAPIKey.Id, updatedKey.Id)
	}
	if len(bulker.ArgumentData.Update) != 1 {
		t.Error("update should be called")
	}
}
