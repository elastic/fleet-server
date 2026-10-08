// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package model

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		want  []ToRetireAPIKeyIdsItems
	}{
		{
			name: "no API key marked to be retired",
			agent: Agent{
				AccessAPIKeyID: "access_api_key_id",
				Outputs: map[string]*PolicyOutput{
					"p1": {APIKeyID: "p1_api_key_id"}, //nolint:gosec // test data, not real credentials
					"p2": {APIKeyID: "p2_api_key_id"}, //nolint:gosec // test data, not real credentials
				},
			},
			want: []ToRetireAPIKeyIdsItems{{ID: "access_api_key_id", Output: "", RetiredAt: ""},
				{ID: "p1_api_key_id", Output: "p1", RetiredAt: ""},
				{ID: "p2_api_key_id", Output: "p2", RetiredAt: ""}},
		},
		{
			name: "with API key marked to be retired",
			agent: Agent{
				AccessAPIKeyID: "access_api_key_id",
				Outputs: map[string]*PolicyOutput{
					"p1": { //nolint:gosec // test data, not real credentials
						APIKeyID: "p1_api_key_id",
						ToRetireAPIKeyIds: []ToRetireAPIKeyIdsItems{{
							ID:     "p1_to_retire_key",
							Output: "remote",
						}}},
					"p2": { //nolint:gosec // test data, not real credentials
						APIKeyID: "p2_api_key_id",
						ToRetireAPIKeyIds: []ToRetireAPIKeyIdsItems{{
							ID:     "p2_to_retire_key",
							Output: "remote",
						}}},
				},
			},
			want: []ToRetireAPIKeyIdsItems{{ID: "access_api_key_id", Output: "", RetiredAt: ""},
				{ID: "p1_api_key_id", Output: "p1", RetiredAt: ""},
				{ID: "p2_api_key_id", Output: "p2", RetiredAt: ""},
				{ID: "p1_to_retire_key", Output: "remote", RetiredAt: ""},
				{ID: "p2_to_retire_key", Output: "remote", RetiredAt: ""}},
		},
		{
			name: "API key empty",
			agent: Agent{
				AccessAPIKeyID: "access_api_key_id",
				Outputs: map[string]*PolicyOutput{
					"p1": {APIKeyID: ""},
				},
			},
			want: []ToRetireAPIKeyIdsItems{{ID: "access_api_key_id", Output: "", RetiredAt: ""}},
		},
		{
			name: "retired API key empty",
			agent: Agent{
				AccessAPIKeyID: "access_api_key_id",
				Outputs: map[string]*PolicyOutput{
					"p1": { //nolint:gosec // test data, not real credentials
						APIKeyID: "p1_api_key_id",
						ToRetireAPIKeyIds: []ToRetireAPIKeyIdsItems{{
							ID: "",
						}}},
				},
			},
			want: []ToRetireAPIKeyIdsItems{{ID: "access_api_key_id", Output: "", RetiredAt: ""},
				{ID: "p1_api_key_id", Output: "p1", RetiredAt: ""}},
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

func TestAgentComputeTagsHash(t *testing.T) {
	hash := func(t *testing.T, tags ...string) string {
		t.Helper()
		got, err := (&Agent{Tags: tags}).ComputeTagsHash()
		require.NoError(t, err)
		return got
	}

	t.Run("no tags give an empty hash", func(t *testing.T) {
		assert.Empty(t, hash(t))
		got, err := (&Agent{Tags: []string{}}).ComputeTagsHash()
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("same tags give the same hash", func(t *testing.T) {
		first := hash(t, "a", "b")
		assert.NotEmpty(t, first)
		assert.Equal(t, first, hash(t, "a", "b"))
	})

	t.Run("order and duplicates do not change the hash", func(t *testing.T) {
		assert.Equal(t, hash(t, "a", "b"), hash(t, "b", "a", "b"))
	})

	t.Run("different tags give a different hash", func(t *testing.T) {
		assert.NotEqual(t, hash(t, "a", "b"), hash(t, "a", "c"))
	})
}

func TestPolicyDataFeatureEnabled(t *testing.T) {
	tests := []struct {
		name       string
		policyData *PolicyData
		want       bool
	}{
		{
			name:       "nil policy data",
			policyData: nil,
			want:       false,
		},
		{
			name:       "nil agent section",
			policyData: &PolicyData{},
			want:       false,
		},
		{
			name:       "no features",
			policyData: &PolicyData{Agent: map[string]any{}},
			want:       false,
		},
		{
			name: "feature absent",
			policyData: &PolicyData{Agent: map[string]any{
				"features": map[string]any{"fqdn": map[string]any{"enabled": true}},
			}},
			want: false,
		},
		{
			name: "enabled false",
			policyData: &PolicyData{Agent: map[string]any{
				"features": map[string]any{FeatureIncludeTagsInEvents: map[string]any{"enabled": false}},
			}},
			want: false,
		},
		{
			name: "enabled true",
			policyData: &PolicyData{Agent: map[string]any{
				"features": map[string]any{FeatureIncludeTagsInEvents: map[string]any{"enabled": true}},
			}},
			want: true,
		},
		{
			name: "enabled as string",
			policyData: &PolicyData{Agent: map[string]any{
				"features": map[string]any{FeatureIncludeTagsInEvents: map[string]any{"enabled": "true"}},
			}},
			want: false,
		},
		{
			name: "plain boolean form",
			policyData: &PolicyData{Agent: map[string]any{
				"features": map[string]any{FeatureIncludeTagsInEvents: true},
			}},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.policyData.FeatureEnabled(FeatureIncludeTagsInEvents))
		})
	}
}
