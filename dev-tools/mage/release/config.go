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
	return newgitHubClient(token).latestReleaseBefore(owner, repo, current)
}

const (
	releasesLookupOwner = "elastic"
	releasesLookupRepo  = "fleet-server"
)

// ensureLatestRelease sets LatestRelease when unset by querying fleet-server releases/tags.
func ensureLatestRelease(c *ReleaseConfig) error {
	if c.LatestRelease != "" {
		return nil
	}
	if c.CurrentRelease == "" {
		return fmt.Errorf("CurrentRelease is required to resolve LatestRelease")
	}

	latest, err := fetchLatestReleaseBefore(c.GitHubToken, releasesLookupOwner, releasesLookupRepo, c.CurrentRelease)
	if err != nil {
		return fmt.Errorf("failed to resolve LatestRelease from GitHub: %w", err)
	}
	c.LatestRelease = latest
	printf("Resolved LatestRelease from %s/%s: %s\n", releasesLookupOwner, releasesLookupRepo, latest)
	return nil
}

// validateReleaseConfig checks if the configuration is valid for release workflows.
func validateReleaseConfig(c *ReleaseConfig) error {
	if c.CurrentRelease == "" {
		return fmt.Errorf("CurrentRelease is required")
	}

	if !c.DryRun && c.GitHubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN is required when not in dry-run mode")
	}

	return nil
}
