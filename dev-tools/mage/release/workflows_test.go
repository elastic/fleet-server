// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLabelHelpers(t *testing.T) {
	require.Equal(t, "backport-9.6", backportLabel("9.6"))

	labels := prAMainLabels("9.6")
	require.True(t, contains(labels, mergeLabelFFDay))
	require.True(t, contains(labels, "backport-9.6"))
	require.False(t, contains(labels, mergeLabelAfterImages), "PR-A must not include merge:3-after-images (PR-C omitted)")

	require.True(t, contains(prBReleaseLabels(), mergeLabelAfterBranch))
	require.True(t, contains(patchVersionBumpLabels(), mergeLabelAfterRelease))
	require.False(t, contains(patchVersionBumpLabels(), "docs"), "patch bump must not include docs label")
}

func TestPRBodiesMentionFleetScope(t *testing.T) {
	cfg := &ReleaseConfig{
		CurrentRelease:          "9.6.1",
		LatestRelease:           "9.6.0",
		NextRelease:             "9.6.2",
		NextProjectMinorVersion: "9.7.0",
		BaseBranch:              "main",
		ReleaseBranch:           "9.6",
	}

	require.Contains(t, prAMainBody(cfg), "version/version.go")
	require.Contains(t, prBReleaseBody(cfg), "no docs/test-env")
	body := patchVersionBumpBody(cfg)
	require.Contains(t, body, "to 9.6.1")
	require.NotContains(t, body, "Merge after the release of")
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
