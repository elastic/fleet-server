// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"testing"

	"github.com/stretchr/testify/require"

	devtools "github.com/elastic/fleet-server/v7/dev-tools/mage"
)

func TestValidateReleaseConfig(t *testing.T) {
	require.Error(t, ValidateReleaseConfig(&ReleaseConfig{DryRun: true, LatestRelease: "9.4.0"}))
	require.Error(t, ValidateReleaseConfig(&ReleaseConfig{CurrentRelease: "9.5.0", LatestRelease: "9.4.0"}))
	require.NoError(t, ValidateReleaseConfig(&ReleaseConfig{
		CurrentRelease: "9.5.0",
		LatestRelease:  "9.4.0",
		DryRun:         true,
	}))
}

func TestEnsureLatestRelease(t *testing.T) {
	orig := fetchLatestReleaseBefore
	t.Cleanup(func() { fetchLatestReleaseBefore = orig })
	fetchLatestReleaseBefore = func(token, owner, repo, current string) (string, error) {
		return "9.4.3", nil
	}

	cfg := &ReleaseConfig{CurrentRelease: "9.5.0", DryRun: true}
	require.NoError(t, EnsureLatestRelease(cfg))
	require.Equal(t, "9.4.3", cfg.LatestRelease)

	cfg.LatestRelease = "9.4.0"
	require.NoError(t, EnsureLatestRelease(cfg))
	require.Equal(t, "9.4.0", cfg.LatestRelease)
}

func TestLoadReleaseSettings(t *testing.T) {
	t.Setenv("CURRENT_RELEASE", "9.5.0")
	t.Setenv("DRY_RUN", "true")
	settings, err := devtools.LoadReleaseSettings()
	require.NoError(t, err)
	require.NoError(t, settings.RequireRelease())
	require.Equal(t, "9.5.0", settings.CurrentRelease)
	require.True(t, settings.DryRun)
}
