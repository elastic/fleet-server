// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"strings"

	"github.com/google/go-github/v68/github"
)

// PR label sets match vault-bot release PRs for fleet-server.
var (
	bumpMainPRLabels     = []string{"backport-skip", "skip-changelog"}
	nextReleasePRLabels  = []string{"Team:Automation", "release", "skip-changelog"}
	backportNextPRLabels = []string{"Team:Automation", "release", "impact:critical", "skip-changelog"}
	patchReleasePRLabels = []string{"Team:Automation", "release", "docs", "in progress", "skip-changelog"}
)

func checkRequirements(cfg *ReleaseConfig) error {
	parts := strings.Split(cfg.CurrentRelease, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid version format: %s", cfg.CurrentRelease)
	}

	repo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	clean, err := repo.IsClean()
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory is not clean. Please commit or stash changes first")
	}

	return nil
}

// RunMajorMinorRelease creates the release branch and opens the main-branch version bump PR.
func RunMajorMinorRelease(cfg *ReleaseConfig) error {
	fmt.Println("=== Starting Major/Minor Release Workflow ===")

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := checkRequirements(cfg); err != nil {
		return err
	}

	repo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	releaseBranch := cfg.ReleaseBranch
	bumpBranch := bumpVersionBranchName(cfg.NextProjectMinorVersion)

	fmt.Printf("Creating release branch: %s from %s\n", releaseBranch, cfg.BaseBranch)
	if err := repo.EnsureBranchFrom(cfg.BaseBranch, releaseBranch); err != nil {
		return err
	}
	if err := UpdateVersion(cfg.CurrentRelease); err != nil {
		return err
	}
	if _, err := repo.CommitAll("[Release] update version", cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return err
	}

	fmt.Printf("\n--- Creating PR: Bump main to %s ---\n", cfg.NextProjectMinorVersion)
	if err := repo.EnsureBranchFrom(cfg.BaseBranch, bumpBranch); err != nil {
		return err
	}
	if err := UpdateVersion(cfg.NextProjectMinorVersion); err != nil {
		return err
	}
	bumpCommitMsg := fmt.Sprintf("Bump version to %s", cfg.NextProjectMinorVersion)
	if _, err := repo.CommitAll(bumpCommitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return err
	}

	bumpPROpts := PROptions{
		Owner:     cfg.ProjectOwner,
		Repo:      cfg.ProjectRepo,
		Title:     fmt.Sprintf("Bump the version on main to %s", cfg.NextProjectMinorVersion),
		Head:      bumpBranch,
		Base:      cfg.BaseBranch,
		Body:      bumpMainPRBody(cfg.NextProjectMinorVersion),
		Reviewers: cfg.ProjectReviewers,
		Labels:    bumpMainPRLabels,
	}

	if cfg.DryRun {
		fmt.Println("\nDRY RUN: Skipping push and PR creation")
		fmt.Printf("Release branch prepared: %s\n", releaseBranch)
		fmt.Printf("Bump branch prepared: %s\n", bumpBranch)
		fmt.Println("Review changes with 'git diff'")
		return nil
	}

	if err := repo.CheckoutBranch(releaseBranch); err != nil {
		return err
	}
	if err := repo.Push("origin"); err != nil {
		return err
	}

	gh := NewGitHubClient(cfg.GitHubToken)
	bumpPR, err := finalizePR(repo, gh, bumpBranch, cfg.BaseBranch, bumpPROpts)
	if err != nil {
		return err
	}

	fmt.Printf("\n=== Major/Minor Release Workflow Complete ===\n")
	fmt.Printf("Release branch pushed: %s\n", releaseBranch)
	if bumpPR != nil {
		fmt.Printf("Bump main PR: %s\n", bumpPR.GetHTMLURL())
	} else {
		fmt.Println("Bump main PR: not created (already up to date)")
	}
	fmt.Println("\nRun 'mage release:runNextRelease' to open next-release and backport PRs")

	return nil
}

// RunNextRelease opens PRs for the next patch version and mergify backport rule.
func RunNextRelease(cfg *ReleaseConfig) error {
	fmt.Println("=== Starting Next Release Workflow ===")

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := checkRequirements(cfg); err != nil {
		return err
	}

	repo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	releaseBranch := cfg.ReleaseBranch
	nextVersionBranch := nextVersionBranchName(cfg.NextRelease)
	backportBranch := backportNextBranchName(cfg.NextProjectMinorVersion)
	backportLabel := fmt.Sprintf("backport-%s", cfg.ReleaseBranch)

	fmt.Printf("Using release branch: %s\n", releaseBranch)

	fmt.Printf("\n--- Creating PR 1: Update version to %s ---\n", cfg.NextRelease)
	if err := repo.EnsureBranchFrom(releaseBranch, nextVersionBranch); err != nil {
		return err
	}
	if err := UpdateVersion(cfg.NextRelease); err != nil {
		return err
	}
	nextCommitMsg := fmt.Sprintf("[Release] Update version to %s", cfg.NextRelease)
	if _, err := repo.CommitAll(nextCommitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return err
	}

	fmt.Printf("\n--- Creating PR 2: Add backport rule for %s ---\n", cfg.ReleaseBranch)
	if err := repo.EnsureBranchFrom(cfg.BaseBranch, backportBranch); err != nil {
		return err
	}
	if err := UpdateMergify(cfg.CurrentRelease); err != nil {
		return err
	}
	if _, err := repo.CommitAll("[Release] add-backport-next", cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return err
	}

	nextPROpts := PROptions{
		Owner:     cfg.ProjectOwner,
		Repo:      cfg.ProjectRepo,
		Title:     fmt.Sprintf("[Release] Update version to %s", cfg.NextRelease),
		Head:      nextVersionBranch,
		Base:      releaseBranch,
		Body:      nextReleasePRBody(cfg.NextRelease, cfg.CurrentRelease),
		Reviewers: cfg.ProjectReviewers,
		Labels:    nextReleasePRLabels,
	}

	backportLabels := append([]string(nil), backportNextPRLabels...)
	backportLabels = append(backportLabels, backportLabel)

	backportPROpts := PROptions{
		Owner:     cfg.ProjectOwner,
		Repo:      cfg.ProjectRepo,
		Title:     fmt.Sprintf("backport: Add %s branch", cfg.ReleaseBranch),
		Head:      backportBranch,
		Base:      cfg.BaseBranch,
		Body:      backportNextPRBody(cfg.ReleaseBranch),
		Reviewers: cfg.ProjectReviewers,
		Labels:    backportLabels,
	}

	if cfg.DryRun {
		fmt.Println("\nDRY RUN: Skipping push and PR creation")
		fmt.Printf("Next version branch prepared: %s\n", nextVersionBranch)
		fmt.Printf("Backport branch prepared: %s\n", backportBranch)
		fmt.Println("Review changes with 'git diff'")
		return nil
	}

	gh := NewGitHubClient(cfg.GitHubToken)

	backportPR, err := finalizePR(repo, gh, backportBranch, cfg.BaseBranch, backportPROpts)
	if err != nil {
		return err
	}

	nextPR, err := finalizePR(repo, gh, nextVersionBranch, releaseBranch, nextPROpts)
	if err != nil {
		return err
	}

	fmt.Printf("\n=== Next Release Workflow Complete ===\n")
	if backportPR != nil {
		fmt.Printf("Backport PR: %s\n", backportPR.GetHTMLURL())
	} else {
		fmt.Println("Backport PR: not created (already up to date)")
	}
	if nextPR != nil {
		fmt.Printf("Next version PR: %s\n", nextPR.GetHTMLURL())
	} else {
		fmt.Println("Next version PR: not created (already up to date)")
	}

	return nil
}

// RunPatchRelease opens a version bump PR into the release branch.
func RunPatchRelease(cfg *ReleaseConfig) error {
	fmt.Println("=== Starting Patch Release Workflow ===")

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := checkRequirements(cfg); err != nil {
		return err
	}

	repo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	releaseBranch := cfg.ReleaseBranch
	if releaseBranch == "" {
		releaseBranch = inferReleaseBranch(cfg.CurrentRelease)
	}

	patchBranch := patchDocsBranchName(cfg.CurrentRelease)
	fmt.Printf("Using release branch: %s\n", releaseBranch)
	fmt.Printf("\n--- Creating PR: Patch version %s ---\n", cfg.CurrentRelease)

	if err := repo.EnsureBranchFrom(releaseBranch, patchBranch); err != nil {
		return err
	}
	if err := UpdateVersion(cfg.CurrentRelease); err != nil {
		return err
	}
	if _, err := repo.CommitAll("[Release] update version", cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return err
	}

	patchPROpts := PROptions{
		Owner:     cfg.ProjectOwner,
		Repo:      cfg.ProjectRepo,
		Title:     fmt.Sprintf("docs: update docs versions %s", cfg.CurrentRelease),
		Head:      patchBranch,
		Base:      releaseBranch,
		Body:      patchReleasePRBody(cfg.CurrentRelease),
		Reviewers: cfg.ProjectReviewers,
		Labels:    patchReleasePRLabels,
	}

	if cfg.DryRun {
		fmt.Println("\nDRY RUN: Skipping push and PR creation")
		fmt.Printf("Patch branch prepared: %s\n", patchBranch)
		fmt.Println("Review changes with 'git diff'")
		return nil
	}

	gh := NewGitHubClient(cfg.GitHubToken)
	patchPR, err := finalizePR(repo, gh, patchBranch, releaseBranch, patchPROpts)
	if err != nil {
		return err
	}

	fmt.Printf("\n=== Patch Release Workflow Complete ===\n")
	if patchPR != nil {
		fmt.Printf("Patch PR: %s\n", patchPR.GetHTMLURL())
	} else {
		fmt.Println("Patch PR: not created (already up to date)")
	}

	return nil
}

func bumpVersionBranchName(nextMinorVersion string) string {
	return fmt.Sprintf("bump-version-%s", nextMinorVersion)
}

func nextVersionBranchName(nextRelease string) string {
	return fmt.Sprintf("update-version-next-%s", nextRelease)
}

func backportNextBranchName(nextProjectMinorVersion string) string {
	return fmt.Sprintf("add-backport-next-%s", nextProjectMinorVersion)
}

func patchDocsBranchName(version string) string {
	return fmt.Sprintf("update-docs-version-%s", version)
}

func bumpMainPRBody(nextMinorVersion string) string {
	return fmt.Sprintf("Bump the version on main to %s.", nextMinorVersion)
}

func nextReleasePRBody(nextRelease, currentRelease string) string {
	return fmt.Sprintf(`Updates references to the new release %s.

Merge after the release %s.
`, nextRelease, currentRelease)
}

func backportNextPRBody(releaseBranch string) string {
	return fmt.Sprintf(`Merge as soon as %s branch was created.

Auto-merge is not yet supported, see https://github.com/Mergifyio/mergify-engine/discussions/2821
`, releaseBranch)
}

func patchReleasePRBody(version string) string {
	return fmt.Sprintf(`Updates docs versions to %s.

Merge before the final Release build.
`, version)
}

func finalizePR(repo *GitRepo, gh *GitHubClient, branchName, baseBranch string, opts PROptions) (*github.PullRequest, error) {
	if err := repo.CheckoutBranch(branchName); err != nil {
		return nil, err
	}

	existingPR, found, err := gh.FindOpenPR(opts.Owner, opts.Repo, opts.Head, opts.Base)
	if err != nil {
		return nil, err
	}
	if found {
		gh.ensurePRLabels(opts.Owner, opts.Repo, existingPR.GetNumber(), opts.Labels)
		fmt.Printf("Open PR already exists #%d: %s\n", existingPR.GetNumber(), existingPR.GetHTMLURL())
		return existingPR, nil
	}

	ahead, err := repo.HasCommitsAheadOf(baseBranch)
	if err != nil {
		return nil, err
	}
	if !ahead {
		fmt.Printf("No new commits on %s compared to %s; skipping push and PR creation\n", branchName, baseBranch)
		return nil, nil
	}

	if err := repo.Push("origin"); err != nil {
		return nil, err
	}

	return gh.CreatePR(opts)
}
