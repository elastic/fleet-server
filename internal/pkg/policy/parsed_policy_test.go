// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package policy

import (
	"context"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

//go:embed testdata/test_policy.json
var testPolicy string

//go:embed testdata/test_policy_minified.json
var minified string

//go:embed testdata/logstash_output_policy.json
var logstashOutputPolicy string

//go:embed testdata/remote_es_policy.json
var testPolicyRemoteES string

//go:embed testdata/policy_with_secrets_mixed.json
var policyWithSecretsMixed string

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

// TestParsedPolicyMixedSecretsReplacement tests that secrets specified in a policy
// using either the `secrets.<path-to-key>.<key>.id:<secret ref>` format or the
// `<path>: $co.elastic.secret{<secret ref>}` format are both replaced correctly.
func TestParsedPolicyMixedSecretsReplacement(t *testing.T) {
	// Load the model into the policy object
	var m model.Policy
	var d model.PolicyData
	err := json.Unmarshal([]byte(policyWithSecretsMixed), &d)
	require.NoError(t, err)

	m.Data = &d

	bulker := ftesting.NewMockBulk()
	pp, err := NewParsedPolicy(context.TODO(), bulker, m)
	require.NoError(t, err)

	// Validate that secrets were identified
	require.Len(t, pp.SecretKeys, 4)
	require.Contains(t, pp.SecretKeys, "outputs.fs-output.type")
	require.Contains(t, pp.SecretKeys, "outputs.fs-output.ssl.key")
	require.Contains(t, pp.SecretKeys, "inputs.0.streams.0.auth.basic.password")
	require.Contains(t, pp.SecretKeys, "inputs.0.streams.1.auth.basic.password")

	// Validate that secret references were replaced
	firstInputStreams := pp.Inputs[0]["streams"].([]any)
	firstInputFirstStream := firstInputStreams[0].(map[string]any)
	firstInputSecondStream := firstInputStreams[1].(map[string]any)
	require.Equal(t, "0Mx2UZoBTAyw4gQKSaao_value", firstInputFirstStream["auth.basic.password"])
	require.Equal(t, "0Mx2UZoBTAyw4gQKSaao_value", firstInputSecondStream["auth.basic.password"])
	require.Equal(t, "abcdef123_value", pp.Policy.Data.Outputs["fs-output"]["type"])
	require.Equal(t, "w8yELZoBTAyw4gQK9KZ7_value", pp.Policy.Data.Outputs["fs-output"]["ssl"].(map[string]interface{})["key"])
}
