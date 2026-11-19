// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"strings"

	devtools "github.com/elastic/fleet-server/v7/dev-tools/mage"
)

// selectLatestReleaseBefore picks the highest same-major version strictly less than current.
// GitHub release tags are external input, so they are parsed here at the boundary.
func selectLatestReleaseBefore(versions []string, currentVersion string) (string, error) {
	current, err := devtools.ParseReleaseVersion(currentVersion)
	if err != nil {
		return "", err
	}

	var best *devtools.ReleaseVersion
	for _, raw := range versions {
		candidate, err := devtools.ParseReleaseVersion(raw)
		if err != nil {
			continue
		}
		if candidate.Major != current.Major {
			continue
		}
		if !releaseVersionLess(candidate, current) {
			continue
		}
		if best == nil || releaseVersionLess(*best, candidate) {
			c := candidate
			best = &c
		}
	}
	if best == nil {
		return "", fmt.Errorf("no published release found before %s (same major)", currentVersion)
	}
	return best.String(), nil
}

func releaseVersionLess(a, b devtools.ReleaseVersion) bool {
	if a.Major != b.Major {
		return a.Major < b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor < b.Minor
	}
	return a.Patch < b.Patch
}

// branchVersionFromRelease returns the X.Y branch name from an X.Y or X.Y.Z
// release string after validating that every component is a non-negative integer.
func branchVersionFromRelease(version string) (string, error) {
	version = strings.TrimSpace(version)
	parts := strings.Split(version, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return "", fmt.Errorf("invalid version format: %s (expected X.Y or X.Y.Z)", version)
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasPrefix(part, "+") {
			return "", fmt.Errorf("invalid version format: %s (expected X.Y or X.Y.Z)", version)
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return "", fmt.Errorf("invalid version format: %s (expected X.Y or X.Y.Z)", version)
			}
		}
	}
	return fmt.Sprintf("%s.%s", parts[0], parts[1]), nil
}
