// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const testInvalidFooPatch = "9.foo.0"

func TestSelectLatestReleaseBefore(t *testing.T) {
	versions := []string{testVersion940, "9.4.3", testVersion950, "v9.3.2", "8.19.1", "not-a-version"}
	got, err := selectLatestReleaseBefore(versions, testVersion950)
	require.NoError(t, err)
	require.Equal(t, "9.4.3", got)
}

func TestParseSemverRejectsSignedComponents(t *testing.T) {
	for _, version := range []string{"-1.0.0", "+9.6.0", "9.-1.0", "9.6.+1", testInvalidFooPatch} {
		_, err := parseSemver(version)
		require.Error(t, err, "parseSemver(%q) expected error", version)
	}
	got, err := parseSemver("9.6.0")
	require.NoError(t, err)
	require.Equal(t, "9.6.0", got.String())
}

func TestBranchVersionFromRelease(t *testing.T) {
	got, err := branchVersionFromRelease(testVersion950)
	require.NoError(t, err)
	require.Equal(t, testVersionXY, got)

	got, err = branchVersionFromRelease(testVersionXY)
	require.NoError(t, err)
	require.Equal(t, testVersionXY, got)

	for _, version := range []string{"9.foo", testInvalidFooPatch, "-1.2", "9.+1.0"} {
		_, err := branchVersionFromRelease(version)
		require.Error(t, err, "branchVersionFromRelease(%q) expected error", version)
	}
}
