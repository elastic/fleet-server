// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

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
