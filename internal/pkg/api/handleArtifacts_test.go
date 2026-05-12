// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestPolicyHasArtifact(t *testing.T) {
	policyData := &model.PolicyData{
		Inputs: []map[string]any{
			{
				"type": "logfile",
				"id":   "logfile-1",
			},
			{
				"type": "endpoint",
				"id":   "endpoint-1",
				"artifact_manifest": map[string]any{
					"manifest_version": "1.0.28",
					"schema_version":   "v1",
					"artifacts": map[string]any{
						"endpoint-trustlist-windows-v1": map[string]any{
							"decoded_sha256": "74c2255ce31e0b48ada298ed6dacf6d1be7b0fb40c1bcb251d2da66f4b060acf",
							"decoded_size":   float64(338),
						},
						"endpoint-trustlist-linux-v1": map[string]any{
							"decoded_sha256": "d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
							"decoded_size":   float64(14),
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name string
		id   string
		sha2 string
		want bool
	}{
		{
			name: "matching artifact",
			id:   "endpoint-trustlist-windows-v1",
			sha2: "74c2255ce31e0b48ada298ed6dacf6d1be7b0fb40c1bcb251d2da66f4b060acf",
			want: true,
		},
		{
			name: "matching linux artifact",
			id:   "endpoint-trustlist-linux-v1",
			sha2: "d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
			want: true,
		},
		{
			name: "unknown artifact id",
			id:   "endpoint-blocklist-windows-v1",
			sha2: "74c2255ce31e0b48ada298ed6dacf6d1be7b0fb40c1bcb251d2da66f4b060acf",
			want: false,
		},
		{
			name: "wrong sha256 for known id",
			id:   "endpoint-trustlist-windows-v1",
			sha2: "0000000000000000000000000000000000000000000000000000000000000000",
			want: false,
		},
		{
			name: "empty id",
			id:   "",
			sha2: "74c2255ce31e0b48ada298ed6dacf6d1be7b0fb40c1bcb251d2da66f4b060acf",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyHasArtifact(policyData, tt.id, tt.sha2)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPolicyHasArtifact_NoInputs(t *testing.T) {
	pd := &model.PolicyData{}
	assert.False(t, policyHasArtifact(pd, "endpoint-trustlist-linux-v1", "abc123"))
}

func TestPolicyHasArtifact_NoArtifactManifest(t *testing.T) {
	pd := &model.PolicyData{
		Inputs: []map[string]any{
			{"type": "logfile"},
		},
	}
	assert.False(t, policyHasArtifact(pd, "endpoint-trustlist-linux-v1", "abc123"))
}

func TestPolicyHasArtifact_MultipleInputsWithArtifacts(t *testing.T) {
	pd := &model.PolicyData{
		Inputs: []map[string]any{
			{"type": "logfile"},
			{
				"type": "endpoint",
				"artifact_manifest": map[string]any{
					"artifacts": map[string]any{
						"endpoint-trustlist-linux-v1": map[string]any{
							"decoded_sha256": "aaaa",
						},
					},
				},
			},
			{
				"type": "another-endpoint",
				"artifact_manifest": map[string]any{
					"artifacts": map[string]any{
						"endpoint-blocklist-linux-v1": map[string]any{
							"decoded_sha256": "bbbb",
						},
					},
				},
			},
		},
	}
	assert.True(t, policyHasArtifact(pd, "endpoint-trustlist-linux-v1", "aaaa"))
	assert.True(t, policyHasArtifact(pd, "endpoint-blocklist-linux-v1", "bbbb"))
	assert.False(t, policyHasArtifact(pd, "endpoint-trustlist-linux-v1", "bbbb"))
}
