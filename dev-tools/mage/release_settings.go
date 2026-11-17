// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReleaseSettings holds configuration for release automation (feature freeze / patch).
// CURRENT_RELEASE is optional during general loads; release targets call RequireRelease()
// before running workflows.
type ReleaseSettings struct {
	CurrentRelease          string
	LatestRelease           string
	NextRelease             string
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

// RequireRelease ensures CURRENT_RELEASE was provided so inferred release fields are set.
func (s *ReleaseSettings) RequireRelease() error {
	if s.CurrentRelease == "" {
		return fmt.Errorf("CURRENT_RELEASE environment variable is required")
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
// When CURRENT_RELEASE is unset, non-version fields may still be overridden; inferred
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

	currentRelease := os.Getenv("CURRENT_RELEASE")
	if currentRelease == "" {
		return nil
	}

	return s.populateFromCurrent(currentRelease)
}

func (s *ReleaseSettings) populateFromCurrent(currentRelease string) error {
	parsed, err := ParseReleaseVersion(currentRelease)
	if err != nil {
		return err
	}

	s.CurrentRelease = parsed.String()
	s.LatestRelease = InferLatestRelease(parsed)
	s.NextRelease = InferNextRelease(parsed)
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
// prerelease or build metadata (e.g. CURRENT_RELEASE=9.5.0).
func ParseReleaseVersion(currentRelease string) (ReleaseVersion, error) {
	version := strings.TrimPrefix(strings.TrimSpace(currentRelease), "v")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return ReleaseVersion{}, fmt.Errorf("invalid version format: %s (expected major.minor.patch)", currentRelease)
	}
	major, err := parseUnsignedComponent(parts[0])
	if err != nil {
		return ReleaseVersion{}, fmt.Errorf("invalid major version: %s", parts[0])
	}
	minor, err := parseUnsignedComponent(parts[1])
	if err != nil {
		return ReleaseVersion{}, fmt.Errorf("invalid minor version: %s", parts[1])
	}
	patch, err := parseUnsignedComponent(parts[2])
	if err != nil {
		return ReleaseVersion{}, fmt.Errorf("invalid patch version: %s", parts[2])
	}
	return ReleaseVersion{Major: major, Minor: minor, Patch: patch}, nil
}

func parseUnsignedComponent(s string) (int, error) {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		return 0, fmt.Errorf("invalid unsigned integer: %q", s)
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid unsigned integer: %q", s)
		}
	}
	return strconv.Atoi(s)
}

// InferLatestRelease calculates the previous release version (patch - 1).
// For minor releases (patch == 0), returns empty string; callers may resolve via GitHub.
func InferLatestRelease(v ReleaseVersion) string {
	if v.Patch == 0 {
		return ""
	}
	return ReleaseVersion{Major: v.Major, Minor: v.Minor, Patch: v.Patch - 1}.String()
}

// InferNextRelease returns the next patch version (patch + 1).
func InferNextRelease(v ReleaseVersion) string {
	return ReleaseVersion{Major: v.Major, Minor: v.Minor, Patch: v.Patch + 1}.String()
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
