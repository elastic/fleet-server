// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInferLatestRelease(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
		wantErr bool
	}{
		{name: "valid version", version: "9.6.2", want: "9.6.1"},
		{name: "patch version is 0", version: "9.6.0", want: ""},
		{name: "invalid format", version: "9.6", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseReleaseVersion(tt.version)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, InferLatestRelease(parsed))
		})
	}
}

func TestInferNextRelease(t *testing.T) {
	parsed, err := ParseReleaseVersion("9.6.0")
	require.NoError(t, err)
	require.Equal(t, "9.6.1", InferNextRelease(parsed))
}

func TestInferNextProjectMinorVersion(t *testing.T) {
	parsed, err := ParseReleaseVersion("9.6.0")
	require.NoError(t, err)
	require.Equal(t, "9.7.0", InferNextProjectMinorVersion(parsed))
}

func TestLoadReleaseSettingsFromEnv(t *testing.T) {
	keys := []string{
		"BASE_BRANCH",
		"CURRENT_RELEASE",
		"DRY_RUN",
		"GITHUB_TOKEN",
		"GIT_AUTHOR_EMAIL",
		"GIT_AUTHOR_NAME",
		"PROJECT_OWNER",
		"PROJECT_REPO",
		"PROJECT_REVIEWERS",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
	t.Setenv("CURRENT_RELEASE", "9.6.0")

	s, err := LoadReleaseSettings()
	require.NoError(t, err)
	require.Equal(t, "9.6.0", s.CurrentRelease)
	require.Equal(t, "9.6", s.ReleaseBranch)
	require.Equal(t, "9.6.1", s.NextRelease)
	require.Equal(t, "main", s.BaseBranch)
	require.Equal(t, "elastic", s.ProjectOwner)
	require.Equal(t, "fleet-server", s.ProjectRepo)
	require.Equal(t, "9.7.0", s.NextProjectMinorVersion)
	require.Equal(t, "9.7", s.NextProjectMinorBranch)
	require.False(t, s.DryRun)
	require.NoError(t, s.RequireRelease())
}

func TestLoadReleaseSettingsDryRun(t *testing.T) {
	t.Setenv("CURRENT_RELEASE", "9.6.0")
	t.Setenv("DRY_RUN", "true")
	s, err := LoadReleaseSettings()
	require.NoError(t, err)
	require.True(t, s.DryRun)

	t.Setenv("DRY_RUN", "1")
	s, err = LoadReleaseSettings()
	require.NoError(t, err)
	require.False(t, s.DryRun)
}

func TestRequireReleaseMissingCurrent(t *testing.T) {
	s := defaultReleaseSettings()
	require.Error(t, s.RequireRelease())
}
