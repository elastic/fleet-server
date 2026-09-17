// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package policy

import (
	"context"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

//go:embed testdata/test_policy.json
var testPolicy string

//go:embed testdata/test_policy_minified.json
var minified string

//go:embed testdata/logstash_output_policy.json
var logstashOutputPolicy string

//go:embed testdata/remote_es_policy.json
var testPolicyRemoteES string

func TestNewParsedPolicy(t *testing.T) {
	// Run two formatting of the same payload to validate that the sha2 remains the same
	testcases := []struct {
		name        string
		payload     string
		defaultName string
	}{{
		name:        "test policy",
		payload:     testPolicy,
		defaultName: "other",
	}, {
		name:        "minified",
		payload:     minified,
		defaultName: "default",
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Load the model into the policy object
			var m model.Policy
			var d model.PolicyData
			err := json.Unmarshal([]byte(tc.payload), &d)
			require.NoError(t, err)
			m.Data = &d

			pp, err := NewParsedPolicy(context.TODO(), nil, m)
			require.NoError(t, err)

			// Now validate output perms hash
			require.Len(t, pp.Roles, 1, "Only expected one role")

			// Validate that default was found
			require.Equal(t, tc.defaultName, pp.Default.Name)
			defaultOutput := pp.Outputs[pp.Default.Name]
			require.NotNil(t, defaultOutput.Role, "output role should be identified")

			expectedSha2 := "d4d0840fe28ca4900129a749b56cee729562c0a88c935192c659252b5b0d762a"
			require.Equal(t, expectedSha2, defaultOutput.Role.Sha2)
		})
	}
}

func TestNewParsedPolicyNoES(t *testing.T) {
	// Load the model into the policy object
	var m model.Policy
	var d model.PolicyData
	err := json.Unmarshal([]byte(logstashOutputPolicy), &d)
	require.NoError(t, err)

	m.Data = &d

	pp, err := NewParsedPolicy(context.TODO(), nil, m)
	require.NoError(t, err)

	// Validate that default was found
	require.Equal(t, "remote_not_es", pp.Default.Name)
}

func TestNewParsedPolicyRemoteES(t *testing.T) {
	// Load the model into the policy object
	var m model.Policy
	var d model.PolicyData
	err := json.Unmarshal([]byte(testPolicyRemoteES), &d)
	require.NoError(t, err)

	m.Data = &d

	pp, err := NewParsedPolicy(context.TODO(), nil, m)
	require.NoError(t, err)

	// Validate that default was found
	require.Equal(t, "remote", pp.Default.Name)
}

// TestParsedPolicyCloneIsolation verifies that mutating any field of a cloned
// ParsedPolicy does not affect the original, covering the fields that processPolicy
// mutates during concurrent fan-out.
func TestParsedPolicyCloneIsolation(t *testing.T) {
	var m model.Policy
	var d model.PolicyData
	require.NoError(t, json.Unmarshal([]byte(testPolicy), &d))
	m.Data = &d
	m.Namespaces = []string{"ns1"}

	original, err := NewParsedPolicy(context.TODO(), nil, m)
	require.NoError(t, err)

	// Seed a known secret key so we can detect cross-contamination.
	original.SecretKeys = []string{"outputs.default.token"}

	clone := original.Clone()

	// Mutate an existing SecretKeys element on the clone — append would reallocate
	// when len==cap and pass even with a shared backing array.
	origFirstKey := original.SecretKeys[0]
	clone.SecretKeys[0] = "mutated"
	require.Equal(t, origFirstKey, original.SecretKeys[0], "SecretKeys: clone mutation affected original")

	// Mutate Policy.Data.Outputs on the clone — both top-level and nested keys,
	// since ProcessOutputSecret mutates nested paths in-place (e.g. ssl.key).
	for k := range clone.Policy.Data.Outputs {
		clone.Policy.Data.Outputs[k]["__clone_marker__"] = "mutated"
		// Add a nested map and mutate inside it to check deep isolation.
		if clone.Policy.Data.Outputs[k]["ssl"] == nil {
			clone.Policy.Data.Outputs[k]["ssl"] = map[string]any{}
		}
		if sslMap, ok := clone.Policy.Data.Outputs[k]["ssl"].(map[string]any); ok {
			sslMap["key"] = "mutated-nested"
		}
	}
	for k, out := range original.Policy.Data.Outputs {
		_, tainted := out["__clone_marker__"]
		require.False(t, tainted, "Policy.Data.Outputs[%q]: top-level clone mutation affected original", k)
		if sslMap, ok := out["ssl"].(map[string]any); ok {
			require.NotEqual(t, "mutated-nested", sslMap["key"],
				"Policy.Data.Outputs[%q].ssl.key: nested clone mutation affected original", k)
		}
	}

	// Snapshot original Roles bytes before mutating the clone.
	originalRoleFirstByte := make(map[string]byte)
	for k, r := range original.Roles {
		if len(r.Raw) > 0 {
			originalRoleFirstByte[k] = r.Raw[0]
		}
	}
	for k, r := range clone.Roles {
		if len(r.Raw) > 0 {
			r.Raw[0] ^= 0xFF
			clone.Roles[k] = r
		}
	}
	for k, want := range originalRoleFirstByte {
		require.Equal(t, want, original.Roles[k].Raw[0],
			"Roles[%q].Raw: clone mutation affected original", k)
	}

	// Mutate Output.Role on the clone.
	for k, out := range clone.Outputs {
		if out.Role != nil {
			out.Role.Sha2 = "mutated"
			clone.Outputs[k] = out
		}
	}
	for k, out := range original.Outputs {
		if out.Role != nil {
			require.NotEqual(t, "mutated", out.Role.Sha2,
				"Outputs[%q].Role.Sha2: clone mutation affected original", k)
		}
	}

	// Mutate Policy.Namespaces on the clone.
	clone.Policy.Namespaces = append(clone.Policy.Namespaces, "ns2")
	require.Equal(t, []string{"ns1"}, original.Policy.Namespaces, "Policy.Namespaces: clone mutation affected original")
}
