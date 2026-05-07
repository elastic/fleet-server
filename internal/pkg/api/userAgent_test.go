// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration && !snapshot

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestValidateUserAgent(t *testing.T) {
	tests := []struct {
		userAgent           string
		verCon              version.Constraints
		err                 error
		elasticAgentVersion string
	}{
		{
			userAgent: "",
			verCon:    nil,
			err:       ErrInvalidUserAgent,
		},
		{
			userAgent: "bad value",
			verCon:    nil,
			err:       ErrInvalidUserAgent,
		},
		{
			userAgent: "eLaStIc AGeNt",
			verCon:    nil,
			err:       ErrInvalidUserAgent,
		},
		{
			userAgent: "eLaStIc AGeNt v7.10.0",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v7.11.1",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v7.12.5",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.0",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.0",
			verCon:    mustBuildConstraints("7.13.1"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.1",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.14.0",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v8.0.0",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.0",
			verCon:    mustBuildConstraints("8.0.0"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.0",
			verCon:    mustBuildConstraints("8.0.0-alpha1"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v8.0.0-alpha1",
			verCon:    mustBuildConstraints("8.0.0-alpha1"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v8.0.0-alpha1",
			verCon:    mustBuildConstraints("8.0.0"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v8.0.0-anything",
			verCon:    mustBuildConstraints("8.0.0"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.15.0-anything",
			verCon:    mustBuildConstraints("8.0.0"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.15.0-anything",
			verCon:    mustBuildConstraints("8.0.0-beta1"),
			err:       nil,
		},
		{
			userAgent:           "Elastic Agent Agentless",
			verCon:              mustBuildConstraints("8.0.0"),
			err:                 nil,
			elasticAgentVersion: "v8.0.0",
		},
		{
			userAgent: "Elastic Agent Agentless",
			verCon:    nil,
			err:       ErrInvalidUserAgent,
		},
	}
	for _, tr := range tests {
		t.Run(tr.userAgent+tr.elasticAgentVersion, func(t *testing.T) {
			_, res := validateUserAgent(context.Background(), zerolog.Nop(), tr.userAgent, tr.elasticAgentVersion, tr.verCon)
			if !errors.Is(tr.err, res) {
				t.Fatalf("err mismatch: %v != %v", tr.err, res)
			}
		})
	}
}

func TestGetVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		userAgentVersion    string
		elasticAgentVersion string
		want                string
		wantErr             error
	}{
		{
			name:                "parses_user_agent_version_first",
			userAgentVersion:    "8.0.0",
			elasticAgentVersion: "9.0.0",
			want:                "8.0.0",
		},
		{
			name:                "strips_v_prefix_on_user_agent_version",
			userAgentVersion:    "v8.1.2",
			elasticAgentVersion: "9.0.0",
			want:                "8.1.2",
		},
		{
			name:                "falls_back_to_elastic_agent_version_header",
			userAgentVersion:    "agentless",
			elasticAgentVersion: "v8.0.0",
			want:                "8.0.0",
		},
		{
			name:                "empty_user_agent_version_uses_header",
			userAgentVersion:    "",
			elasticAgentVersion: "7.14.0",
			want:                "7.14.0",
		},
		{
			name:                "invalid_user_agent_version_invalid_header",
			userAgentVersion:    "not-a-semver",
			elasticAgentVersion: "also-invalid",
			wantErr:             ErrInvalidUserAgent,
		},
		{
			name:                "invalid_user_empty_header",
			userAgentVersion:    "nope",
			elasticAgentVersion: "",
			wantErr:             ErrInvalidUserAgent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := getVersion(tt.userAgentVersion, tt.elasticAgentVersion)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.want, got.String())
		})
	}
}
