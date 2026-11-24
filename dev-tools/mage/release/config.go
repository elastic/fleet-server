// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"

	devtools "github.com/elastic/fleet-server/v7/dev-tools/mage"
)

// ReleaseConfig is the release automation configuration loaded via mage settings.
type ReleaseConfig = devtools.ReleaseSettings

// fetchLatestReleaseBefore looks up the previous published release from GitHub.
// Tests may replace this to avoid network calls.
var fetchLatestReleaseBefore = func(token, owner, repo, current string) (string, error) {
	return newGitHubClient(token).latestReleaseBefore(owner, repo, current)
}

const (
	releasesLookupOwner = "elastic"
	releasesLookupRepo  = "fleet-server"
)

// ensureLatestRelease sets LatestRelease when unset by querying fleet-server releases/tags.
// Feature-freeze and patch workflows do not call this; patch derives the previous
// version with InferLatestRelease. Kept for tests and optional operator use.
func ensureLatestRelease(c *ReleaseConfig) error {
	if err := c.EnsureParsedVersions(); err != nil {
		return err
	}
	if c.LatestReleaseVersion != nil {
		return nil
	}
	if c.LatestRelease != "" {
		return c.SetLatestReleaseFromString(c.LatestRelease)
	}

	latest, err := fetchLatestReleaseBefore(c.GitHubToken, releasesLookupOwner, releasesLookupRepo, c.NextRelease)
	if err != nil {
		return fmt.Errorf("failed to resolve LatestRelease from GitHub: %w", err)
	}
	if err := c.SetLatestReleaseFromString(latest); err != nil {
		return fmt.Errorf("failed to parse LatestRelease from GitHub (%s): %w", latest, err)
	}
	printf("Resolved LatestRelease from %s/%s: %s\n", releasesLookupOwner, releasesLookupRepo, c.LatestRelease)
	return nil
}

// validateReleaseConfig checks if the configuration is valid for release workflows.
func validateReleaseConfig(c *ReleaseConfig) error {
	if err := c.EnsureParsedVersions(); err != nil {
		return err
	}

	if !c.DryRun && c.GitHubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN is required when not in dry-run mode")
	}

	return nil
}
