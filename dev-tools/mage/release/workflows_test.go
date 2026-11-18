// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequireFeatureFreezeNextRelease(t *testing.T) {
	require.NoError(t, requireFeatureFreezeNextRelease(&ReleaseConfig{NextRelease: testVersion960}))
	err := requireFeatureFreezeNextRelease(&ReleaseConfig{NextRelease: testVersion961})
	require.Error(t, err)
	require.Contains(t, err.Error(), "patch 0")
}

func TestLabelHelpers(t *testing.T) {
	require.Equal(t, "backport-"+testReleaseBranch, backportLabel(testReleaseBranch))

	labels := prAMainLabels(testReleaseBranch)
	require.True(t, contains(labels, mergeLabelFFDay))
	require.True(t, contains(labels, "backport-"+testReleaseBranch))
	require.False(t, contains(labels, mergeLabelAfterImages), "PR-A must not include merge:3-after-images (PR-C omitted)")

	require.True(t, contains(prBReleaseLabels(), mergeLabelAfterBranch))
	require.True(t, contains(patchVersionBumpLabels(), mergeLabelAfterRelease))
	require.False(t, contains(patchVersionBumpLabels(), labelDocs), "patch bump must not include docs label")
}

func TestPRBodiesMentionFleetScope(t *testing.T) {
	cfg := &ReleaseConfig{
		NextRelease:             testVersion961,
		LatestRelease:           testVersion960,
		NextProjectMinorVersion: "9.7.0",
		BaseBranch:              testBaseBranch,
		ReleaseBranch:           testReleaseBranch,
	}

	require.Contains(t, prAMainBody(cfg), "version/version.go")
	require.Contains(t, prBReleaseBody(cfg), "no docs/test-env")
	body := patchVersionBumpBody(cfg)
	require.Contains(t, body, "to "+testVersion961)
	require.NotContains(t, body, "Merge after the release of")
}

func contains(ss []string, want string) bool {
	return slices.Contains(ss, want)
}
