// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"os"
	"strings"

	libversion "github.com/elastic/beats/v7/pkg/version"
)

// ReleaseSettings holds configuration for release automation (feature freeze / patch).
// NEXT_RELEASE is optional during general loads; release targets call RequireRelease()
// before running workflows.
type ReleaseSettings struct {
	NextRelease             string
	LatestRelease           string
	NextProjectMinorVersion string
	NextProjectMinorBranch  string

	BaseBranch    string
	ReleaseBranch string

	ProjectOwner     string
	ProjectRepo      string
	GitHubToken      string
	ProjectReviewers []string

	GitAuthorName  string
	GitAuthorEmail string

	DryRun bool
}

// LoadReleaseSettings reads release settings from environment variables.
func LoadReleaseSettings() (*ReleaseSettings, error) {
	s := defaultReleaseSettings()
	if err := s.loadFromEnv(); err != nil {
		return nil, err
	}
	return s, nil
}

// RequireRelease ensures NEXT_RELEASE was provided so inferred release fields are set.
func (s *ReleaseSettings) RequireRelease() error {
	if s.NextRelease == "" {
		return fmt.Errorf("NEXT_RELEASE environment variable is required")
	}
	return nil
}

func defaultReleaseSettings() *ReleaseSettings {
	return &ReleaseSettings{
		BaseBranch:       "main",
		ProjectOwner:     "elastic",
		ProjectRepo:      "fleet-server",
		GitAuthorName:    "elasticmachine",
		GitAuthorEmail:   "infra-root+elasticmachine@elastic.co",
		ProjectReviewers: []string{"elastic/elastic-agent-control-plane"},
		DryRun:           false,
	}
}

// loadFromEnv overrides release settings from environment variables.
// When NEXT_RELEASE is unset, non-version fields may still be overridden; inferred
// version fields remain empty so unrelated mage targets keep working.
func (s *ReleaseSettings) loadFromEnv() error {
	if v := os.Getenv("BASE_BRANCH"); v != "" {
		s.BaseBranch = v
	}
	if v := os.Getenv("PROJECT_OWNER"); v != "" {
		s.ProjectOwner = v
	}
	if v := os.Getenv("PROJECT_REPO"); v != "" {
		s.ProjectRepo = v
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		s.GitHubToken = v
	}
	if v := os.Getenv("GIT_AUTHOR_NAME"); v != "" {
		s.GitAuthorName = v
	}
	if v := os.Getenv("GIT_AUTHOR_EMAIL"); v != "" {
		s.GitAuthorEmail = v
	}
	if v := os.Getenv("DRY_RUN"); v != "" {
		s.DryRun = v == "true"
	}
	if v := os.Getenv("PROJECT_REVIEWERS"); v != "" {
		s.ProjectReviewers = strings.Split(v, ",")
	}

	nextRelease := os.Getenv("NEXT_RELEASE")
	if nextRelease == "" {
		return nil
	}

	return s.populateFromNext(nextRelease)
}

func (s *ReleaseSettings) populateFromNext(nextRelease string) error {
	parsed, err := ParseReleaseVersion(nextRelease)
	if err != nil {
		return err
	}

	s.NextRelease = parsed.String()
	s.LatestRelease = InferLatestRelease(parsed)
	s.ReleaseBranch = InferReleaseBranch(parsed)
	s.NextProjectMinorVersion = InferNextProjectMinorVersion(parsed)
	s.NextProjectMinorBranch = InferNextProjectMinorBranch(parsed)
	return nil
}

// ReleaseVersion is a parsed major.minor.patch release version.
type ReleaseVersion struct {
	Major, Minor, Patch int
}

func (v ReleaseVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseReleaseVersion parses a release version string as major.minor.patch with no
// prerelease or build metadata (e.g. NEXT_RELEASE=9.5.0).
func ParseReleaseVersion(nextRelease string) (ReleaseVersion, error) {
	v, err := parseStrictReleaseVersion(nextRelease)
	if err != nil {
		return ReleaseVersion{}, err
	}
	return ReleaseVersion{Major: v.Major, Minor: v.Minor, Patch: v.Bugfix}, nil
}

// parseStrictReleaseVersion uses beats/v7/pkg/version (same API as the old
// elastic-agent-libs/version package) and rejects signed components and
// prerelease/build metadata so NEXT_RELEASE stays plain X.Y.Z.
func parseStrictReleaseVersion(nextRelease string) (*libversion.V, error) {
	version := strings.TrimPrefix(strings.TrimSpace(nextRelease), "v")
	if version == "" {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", nextRelease)
	}
	if strings.ContainsAny(version, "-+") {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch without prerelease/build metadata)", nextRelease)
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", nextRelease)
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasPrefix(part, "+") {
			return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", nextRelease)
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", nextRelease)
			}
		}
	}

	v, err := libversion.New(version)
	if err != nil {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch): %w", nextRelease, err)
	}
	if v.Meta != "" {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch without prerelease/build metadata)", nextRelease)
	}
	if v.Major < 0 || v.Minor < 0 || v.Bugfix < 0 {
		return nil, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", nextRelease)
	}
	return v, nil
}

// InferLatestRelease calculates the previous release version (patch - 1).
// For minor releases (patch == 0), returns empty string; callers may resolve via GitHub.
func InferLatestRelease(v ReleaseVersion) string {
	if v.Patch == 0 {
		return ""
	}
	return ReleaseVersion{Major: v.Major, Minor: v.Minor, Patch: v.Patch - 1}.String()
}

// InferReleaseBranch returns the major.minor release branch name.
func InferReleaseBranch(v ReleaseVersion) string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// InferNextProjectMinorVersion returns the next minor version as major.(minor+1).0.
func InferNextProjectMinorVersion(v ReleaseVersion) string {
	return ReleaseVersion{Major: v.Major, Minor: v.Minor + 1, Patch: 0}.String()
}

// InferNextProjectMinorBranch returns the next minor branch as major.(minor+1).
func InferNextProjectMinorBranch(v ReleaseVersion) string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor+1)
}
