// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package model

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestAgentGetNewVersion(t *testing.T) {
	tests := []struct {
		Name    string
		Agent   *Agent
		Ver     string
		WantVer string
	}{
		{
			Name: "nil",
		},
		{
			Name:  "agent no meta empty version",
			Agent: &Agent{},
		},
		{
			Name:    "agent no meta nonempty version",
			Agent:   &Agent{},
			Ver:     "7.14",
			WantVer: "7.14",
		},
		{
			Name: "agent with meta empty new version",
			Agent: &Agent{
				Agent: &AgentMetadata{
					Version: "7.14",
				},
			},
			Ver:     "",
			WantVer: "",
		},
		{
			Name: "agent with meta empty version",
			Agent: &Agent{
				Agent: &AgentMetadata{
					Version: "",
				},
			},
			Ver:     "7.15",
			WantVer: "7.15",
		},
		{
			Name: "agent with meta non empty version",
			Agent: &Agent{
				Agent: &AgentMetadata{
					Version: "7.14",
				},
			},
			Ver:     "7.14",
			WantVer: "",
		},
		{
			Name: "agent with meta new version",
			Agent: &Agent{
				Agent: &AgentMetadata{
					Version: "7.14",
				},
			},
			Ver:     "7.15",
			WantVer: "7.15",
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			newVer := tc.Agent.CheckDifferentVersion(tc.Ver)
			diff := cmp.Diff(tc.WantVer, newVer)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestAgentAPIKeyIDs(t *testing.T) {
	tcs := []struct {
		name  string
		agent Agent
		want  []string
	}{
		{
			name: "no API key marked to be retired",
			agent: Agent{
				AccessAPIKeyID: "access_api_key_id",
				Outputs: map[string]*PolicyOutput{
					"p1": {APIKeyID: "p1_api_key_id"},
					"p2": {APIKeyID: "p2_api_key_id"},
				},
			},
			want: []string{"access_api_key_id", "p1_api_key_id", "p2_api_key_id"},
		},
		{
			name: "with API key marked to be retired",
			agent: Agent{
				AccessAPIKeyID: "access_api_key_id",
				Outputs: map[string]*PolicyOutput{
					"p1": {
						APIKeyID: "p1_api_key_id",
						ToRetireAPIKeyIds: []ToRetireAPIKeyIdsItems{{
							ID: "p1_to_retire_key",
						}}},
					"p2": {
						APIKeyID: "p2_api_key_id",
						ToRetireAPIKeyIds: []ToRetireAPIKeyIdsItems{{
							ID: "p2_to_retire_key",
						}}},
				},
			},
			want: []string{
				"access_api_key_id", "p1_api_key_id", "p2_api_key_id",
				"p1_to_retire_key", "p2_to_retire_key"},
		},
		{
			name: "API key empty",
			agent: Agent{
				AccessAPIKeyID: "access_api_key_id",
				Outputs: map[string]*PolicyOutput{
					"p1": {APIKeyID: ""},
				},
			},
			want: []string{"access_api_key_id"},
		},
		{
			name: "retired API key empty",
			agent: Agent{
				AccessAPIKeyID: "access_api_key_id",
				Outputs: map[string]*PolicyOutput{
					"p1": {
						APIKeyID: "p1_api_key_id",
						ToRetireAPIKeyIds: []ToRetireAPIKeyIdsItems{{
							ID: "",
						}}},
				},
			},
			want: []string{
				"access_api_key_id", "p1_api_key_id"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.agent.APIKeyIDs()

			// if A contains B and B contains A => A = B
			assert.Subset(t, tc.want, got)
			assert.Subset(t, got, tc.want)
		})
	}
}
