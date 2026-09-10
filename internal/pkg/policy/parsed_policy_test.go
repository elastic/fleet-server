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

	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"

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

//go:embed testdata/policy_with_secrets_mixed.json
var policyWithSecretsMixed string

//go:embed testdata/policy_with_otel_secrets.json
var policyWithOtelSecrets []byte

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

	// Agent and Fleet are derived from the cloned Policy.Data in Clone(), so
	// top-level mutations on the clone must not affect the original.
	clone.Agent["__clone_marker__"] = "mutated"
	_, tainted := original.Agent["__clone_marker__"]
	require.False(t, tainted, "Agent: clone mutation affected original")
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
	require.Len(t, pp.SecretKeys, 8)
	require.Contains(t, pp.SecretKeys, "outputs.fs-output.type")
	require.Contains(t, pp.SecretKeys, "outputs.fs-output.ssl.key")
	require.Contains(t, pp.SecretKeys, "inputs.0.streams.0.auth.basic.password")
	require.Contains(t, pp.SecretKeys, "inputs.0.streams.1.auth.basic.password")
	require.Contains(t, pp.SecretKeys, "agent.download.sourceURI")
	require.Contains(t, pp.SecretKeys, "agent.download.ssl.key")
	require.Contains(t, pp.SecretKeys, "fleet.hosts.0")
	require.Contains(t, pp.SecretKeys, "fleet.ssl.key")

	// Validate that secret references were replaced
	firstInputStreams := pp.Inputs[0]["streams"].([]any)
	firstInputFirstStream := firstInputStreams[0].(map[string]any)
	firstInputSecondStream := firstInputStreams[1].(map[string]any)
	require.Equal(t, "0Mx2UZoBTAyw4gQKSaao_value", firstInputFirstStream["auth.basic.password"])
	require.Equal(t, "0Mx2UZoBTAyw4gQKSaao_value", firstInputSecondStream["auth.basic.password"])
	require.Equal(t, "abcdef123_value", pp.Policy.Data.Outputs["fs-output"]["type"])
	require.Equal(t, "w8yELZoBTAyw4gQK9KZ7_value", pp.Policy.Data.Outputs["fs-output"]["ssl"].(map[string]any)["key"])
	require.Equal(t, "bcdefg234_value", pp.Policy.Data.Agent["download"].(map[string]any)["sourceURI"])
	require.Equal(t, "rwXzUJoBxE9I-QCxFt9m_value", pp.Policy.Data.Agent["download"].(map[string]any)["ssl"].(map[string]any)["key"])
	require.Equal(t, "abcdef123_value", pp.Policy.Data.Fleet["hosts"].([]any)[0])
	require.Equal(t, "w8yELZoBTAyw4gQK9KZ7_value", pp.Policy.Data.Fleet["ssl"].(map[string]any)["key"])
}

// TestParsedPolicyOTELSecretsReplacement tests that secrets in OTEL sections of a policy
// (receivers, exporters, processors, extensions, connectors) are replaced correctly.
func TestParsedPolicyOTELSecretsReplacement(t *testing.T) {
	var m model.Policy
	var d model.PolicyData
	err := json.Unmarshal(policyWithOtelSecrets, &d)
	require.NoError(t, err)

	m.Data = &d

	bulker := ftesting.NewMockBulk()
	pp, err := NewParsedPolicy(t.Context(), bulker, m)
	require.NoError(t, err)

	// Validate that OTEL secret keys were identified
	require.Contains(t, pp.SecretKeys, "receivers.otlp.auth")
	require.Contains(t, pp.SecretKeys, "exporters.otlphttp/default.headers.authorization")
	require.Contains(t, pp.SecretKeys, "processors.batch.api_key")
	require.Contains(t, pp.SecretKeys, "extensions.basicauth.password")
	require.Contains(t, pp.SecretKeys, "connectors.spanmetrics.token")

	// Validate that inline secret references were replaced in receivers
	otlpMap := pp.Policy.Data.Receivers["otlp"].(map[string]any)
	require.Equal(t, "receiver-auth-id_value", otlpMap["auth"])

	// Validate that path-based secret references were replaced in exporters
	otlphttpMap := pp.Policy.Data.Exporters["otlphttp/default"].(map[string]any)
	require.Equal(t, "exporter-auth-id_value", otlphttpMap["headers"].(map[string]any)["authorization"])

	// Validate that inline secret references were replaced in processors
	batchMap := pp.Policy.Data.Processors["batch"].(map[string]any)
	require.Equal(t, "processor-key-id_value", batchMap["api_key"])

	// Validate that path-based secret references were replaced in extensions
	basicauthMap := pp.Policy.Data.Extensions["basicauth"].(map[string]any)
	require.Equal(t, "extension-password-id_value", basicauthMap["password"])

	// Validate that inline secret references were replaced in connectors
	spanmetricsMap := pp.Policy.Data.Connectors["spanmetrics"].(map[string]any)
	require.Equal(t, "connector-token-id_value", spanmetricsMap["token"])
}
