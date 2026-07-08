// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubPolicyMonitor struct {
	getPolicy func(ctx context.Context, policyID string) (*model.Policy, error)
}

func (s *stubPolicyMonitor) Run(_ context.Context) error { return nil }
func (s *stubPolicyMonitor) Subscribe(_, _ string, _ int64) (policy.Subscription, error) {
	return nil, nil
}
func (s *stubPolicyMonitor) Unsubscribe(_ policy.Subscription) error     { return nil }
func (s *stubPolicyMonitor) LatestRev(_ context.Context, _ string) int64 { return 0 }
func (s *stubPolicyMonitor) GetPolicy(ctx context.Context, policyID string) (*model.Policy, error) {
	return s.getPolicy(ctx, policyID)
}

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

func TestAuthorizeArtifact(t *testing.T) {
	const (
		policyID   = "test-policy-id"
		artifactID = "endpoint-trustlist-linux-v1"
		sha2       = "d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658"
	)

	policyWithArtifact := &model.Policy{
		Data: &model.PolicyData{
			Inputs: []map[string]any{
				{
					"type": "endpoint",
					"artifact_manifest": map[string]any{
						"artifacts": map[string]any{
							artifactID: map[string]any{
								"decoded_sha256": sha2,
							},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name      string
		agent     *model.Agent
		setupMock func(pm *mockPolicyMonitor)
		wantErr   error
	}{
		{
			name:  "authorized: artifact in policy",
			agent: &model.Agent{PolicyID: policyID},
			setupMock: func(pm *mockPolicyMonitor) {
				pm.On("GetPolicy", context.Background(), policyID).Return(policyWithArtifact, nil)
			},
			wantErr: nil,
		},
		{
			name:  "unauthorized: artifact not in policy",
			agent: &model.Agent{PolicyID: policyID},
			setupMock: func(pm *mockPolicyMonitor) {
				pm.On("GetPolicy", context.Background(), policyID).Return(&model.Policy{
					Data: &model.PolicyData{},
				}, nil)
			},
			wantErr: ErrUnauthorizedArtifact,
		},
		{
			name:  "unauthorized: policy not found maps to 403",
			agent: &model.Agent{PolicyID: policyID},
			setupMock: func(pm *mockPolicyMonitor) {
				pm.On("GetPolicy", context.Background(), policyID).Return(nil, policy.ErrPolicyNotFound)
			},
			wantErr: ErrUnauthorizedArtifact,
		},
		{
			name:  "error: GetPolicy returns unexpected error",
			agent: &model.Agent{PolicyID: policyID},
			setupMock: func(pm *mockPolicyMonitor) {
				pm.On("GetPolicy", context.Background(), policyID).Return(nil, errors.New("elasticsearch unavailable"))
			},
			wantErr: nil, // wrapped, so we check IsUnauthorized is false
		},
		{
			name:      "forbidden: agent has no policy ID",
			agent:     &model.Agent{},
			setupMock: func(pm *mockPolicyMonitor) {},
			wantErr:   ErrAgentPolicyIDMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &mockPolicyMonitor{}
			tt.setupMock(pm)
			at := ArtifactT{pm: pm}

			err := at.authorizeArtifact(context.Background(), tt.agent, artifactID, sha2)

			if tt.name == "error: GetPolicy returns unexpected error" {
				require.Error(t, err)
				assert.False(t, errors.Is(err, ErrUnauthorizedArtifact))
			} else if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			pm.AssertExpectations(t)
		})
	}
}
