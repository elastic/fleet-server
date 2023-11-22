// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package bulk

import (
	"context"
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/stretchr/testify/assert"
)

func Test_hasChangedAndUpdateRemoteOutputConfig(t *testing.T) {
	testcases := []struct {
		name    string
		cfg     map[string]interface{}
		newCfg  map[string]interface{}
		changed bool
	}{
		{
			name: "initial nil",
			cfg:  nil,
			newCfg: map[string]interface{}{
				"type":          "remote_elasticsearch",
				"hosts":         []string{"https://remote-es:443"},
				"service_token": "token1",
			},
			changed: false,
		},
		{
			name: "no changes",
			cfg: map[string]interface{}{
				"type":          "remote_elasticsearch",
				"hosts":         []string{"https://remote-es:443"},
				"service_token": "token1",
			},
			newCfg: map[string]interface{}{
				"type":          "remote_elasticsearch",
				"hosts":         []string{"https://remote-es:443"},
				"service_token": "token1",
			},
			changed: false,
		},
		{
			name: "change to service token",
			cfg: map[string]interface{}{
				"type":          "remote_elasticsearch",
				"hosts":         []string{"https://remote-es:443"},
				"service_token": "token1",
			},
			newCfg: map[string]interface{}{
				"type":          "remote_elasticsearch",
				"hosts":         []string{"https://remote-es:443"},
				"service_token": "token2",
			},
			changed: true,
		},
		{
			name: "change to advanced config",
			cfg: map[string]interface{}{
				"type":                "remote_elasticsearch",
				"hosts":               []string{"https://remote-es:443"},
				"service_token":       "token1",
				"server.memory_limit": "4",
			},
			newCfg: map[string]interface{}{
				"type":                "remote_elasticsearch",
				"hosts":               []string{"https://remote-es:443"},
				"service_token":       "token1",
				"server.memory_limit": "5",
			},
			changed: true,
		}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			log := testlog.SetLogger(t)
			bulker := NewBulker(nil, nil)
			bulker.remoteOutputConfigMap["remote1"] = tc.cfg
			hasChanged := bulker.hasChangedAndUpdateRemoteOutputConfig(log, "remote1", tc.newCfg)
			assert.Equal(t, tc.changed, hasChanged)
			assert.Equal(t, tc.newCfg, bulker.remoteOutputConfigMap["remote1"])
		})
	}
}

func Test_CreateAndGetBulkerNew(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	log := testlog.SetLogger(t)
	bulker := NewBulker(nil, nil)
	outputMap := make(map[string]map[string]interface{})
	outputMap["remote1"] = map[string]interface{}{
		"type":          "remote_elasticsearch",
		"hosts":         []interface{}{"https://remote-es:443"},
		"service_token": "token1",
	}
	newBulker, hasChanged, err := bulker.CreateAndGetBulker(ctx, log, "remote1", outputMap)
	assert.NotNil(t, newBulker)
	assert.Equal(t, false, hasChanged)
	assert.Nil(t, err)
}

func Test_CreateAndGetBulkerExisting(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	log := testlog.SetLogger(t)
	bulker := NewBulker(nil, nil)
	outputBulker := NewBulker(nil, nil)
	bulker.bulkerMap["remote1"] = outputBulker
	outputMap := make(map[string]map[string]interface{})
	cfg := map[string]interface{}{
		"type":          "remote_elasticsearch",
		"hosts":         []interface{}{"https://remote-es:443"},
		"service_token": "token1",
	}
	bulker.remoteOutputConfigMap["remote1"] = cfg
	outputMap["remote1"] = cfg
	newBulker, hasChanged, err := bulker.CreateAndGetBulker(ctx, log, "remote1", outputMap)
	assert.Equal(t, outputBulker, newBulker)
	assert.Equal(t, false, hasChanged)
	assert.Nil(t, err)
}

func Test_CreateAndGetBulkerChanged(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	log := testlog.SetLogger(t)
	bulker := NewBulker(nil, nil)
	outputBulker := NewBulker(nil, nil)
	bulker.bulkerMap["remote1"] = outputBulker
	outputMap := make(map[string]map[string]interface{})
	bulker.remoteOutputConfigMap["remote1"] = map[string]interface{}{
		"type":          "remote_elasticsearch",
		"hosts":         []interface{}{"https://remote-es:443"},
		"service_token": "token1",
	}
	outputMap["remote1"] = map[string]interface{}{
		"type":          "remote_elasticsearch",
		"hosts":         []interface{}{"https://remote-es:443"},
		"service_token": "token2",
	}
	cancelFnCalled := false
	outputBulker.cancelFn = func() { cancelFnCalled = true }
	newBulker, hasChanged, err := bulker.CreateAndGetBulker(ctx, log, "remote1", outputMap)
	assert.NotEqual(t, outputBulker, newBulker)
	assert.Equal(t, true, hasChanged)
	assert.Nil(t, err)
	assert.Equal(t, true, cancelFnCalled)
}
