// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"strings"

	libversion "github.com/elastic/elastic-agent-libs/version"
)

type releaseSemver struct {
	major, minor, patch int
}

func parseSemver(version string) (releaseSemver, error) {
	v, err := parseStrictReleaseVersion(version)
	if err != nil {
		return releaseSemver{}, err
	}
	return releaseSemver{major: v.Major, minor: v.Minor, patch: v.Bugfix}, nil
}

// parseStrictReleaseVersion uses elastic-agent-libs/version and rejects signed
// components and prerelease/build metadata so release versions stay plain X.Y.Z.
func parseStrictReleaseVersion(raw string) (*libversion.V, error) {
	version := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if version == "" {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", raw)
	}
	if strings.ContainsAny(version, "-+") {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch without prerelease/build metadata)", raw)
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", raw)
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasPrefix(part, "+") {
			return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", raw)
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", raw)
			}
		}
	}

	v, err := libversion.New(version)
	if err != nil {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch): %w", raw, err)
	}
	if v.Meta != "" {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch without prerelease/build metadata)", raw)
	}
	if v.Major < 0 || v.Minor < 0 || v.Bugfix < 0 {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", raw)
	}
	return v, nil
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

func (v releaseSemver) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func (v releaseSemver) less(other releaseSemver) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

// selectLatestReleaseBefore picks the highest same-major version strictly less than current.
func selectLatestReleaseBefore(versions []string, currentVersion string) (string, error) {
	current, err := parseSemver(currentVersion)
	if err != nil {
		return "", err
	}

	var best *releaseSemver
	for _, raw := range versions {
		candidate, err := parseSemver(raw)
		if err != nil {
			continue
		}
		if candidate.major != current.major {
			continue
		}
		if !candidate.less(current) {
			continue
		}
		if best == nil || best.less(candidate) {
			c := candidate
			best = &c
		}
	}
	if best == nil {
		return "", fmt.Errorf("no published release found before %s (same major)", currentVersion)
	}
	return best.String(), nil
}
