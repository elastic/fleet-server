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
	require.Error(t, validateReleaseConfig(&ReleaseConfig{DryRun: true, LatestRelease: testVersion940}))
	require.Error(t, validateReleaseConfig(&ReleaseConfig{CurrentRelease: testVersion950, LatestRelease: testVersion940}))
	require.NoError(t, validateReleaseConfig(&ReleaseConfig{
		CurrentRelease: testVersion950,
		LatestRelease:  testVersion940,
		DryRun:         true,
	}))
}

func TestEnsureLatestRelease(t *testing.T) {
	orig := fetchLatestReleaseBefore
	t.Cleanup(func() { fetchLatestReleaseBefore = orig })
	fetchLatestReleaseBefore = func(token, owner, repo, current string) (string, error) {
		return testVersion943, nil
	}

	cfg := &ReleaseConfig{CurrentRelease: testVersion950, DryRun: true}
	require.NoError(t, ensureLatestRelease(cfg))
	require.Equal(t, testVersion943, cfg.LatestRelease)

	cfg.LatestRelease = testVersion940
	require.NoError(t, ensureLatestRelease(cfg))
	require.Equal(t, testVersion940, cfg.LatestRelease)
}

func TestLoadReleaseSettings(t *testing.T) {
	t.Setenv("CURRENT_RELEASE", testVersion950)
	t.Setenv("DRY_RUN", "true")
	settings, err := devtools.LoadReleaseSettings()
	require.NoError(t, err)
	require.NoError(t, settings.RequireRelease())
	require.Equal(t, testVersion950, settings.CurrentRelease)
	require.True(t, settings.DryRun)
}
