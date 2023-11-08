// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package bulk

import (
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/stretchr/testify/assert"
)

func Test_CheckRemoteOutputChanged(t *testing.T) {
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

	expectedCount := 0
	channelCount := 0

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			log := testlog.SetLogger(t)
			bulker := NewBulker(nil, nil)
			bulker.remoteOutputConfigMap["remote1"] = tc.cfg
			bulker.CheckRemoteOutputChanged(log, "remote1", tc.newCfg)

			if tc.changed {
				expectedCount++
			}

			close(bulker.remoteOutputCh)
			for _ = range bulker.remoteOutputCh {
				channelCount++
			}
		})
	}

	assert.Equal(t, expectedCount, channelCount)
}
