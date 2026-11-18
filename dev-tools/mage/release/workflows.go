// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"

	devtools "github.com/elastic/fleet-server/v7/dev-tools/mage"
	"github.com/google/go-github/v68/github"
)

// Shared PR label names (match vault-bot / beats / elastic-agent release PRs).
const (
	labelDocs           = "docs"
	labelInProgress     = "in progress"
	labelRelease        = "release"
	labelSkipChangelog  = "skip-changelog"
	labelTeamAutomation = "Team:Automation"
)

// PR label sets match vault-bot / beats / elastic-agent release PRs.
var (
	releasePRLabels   = []string{labelRelease, labelTeamAutomation, labelSkipChangelog}
	ffReleasePRLabels = []string{labelRelease, labelDocs, labelInProgress, labelTeamAutomation, labelSkipChangelog}
)

// Feature-freeze merge-timing labels (number = RM merge order).
const (
	mergeLabelFFDay        = "merge:1-ff-day"
	mergeLabelAfterBranch  = "merge:2-after-branch"
	mergeLabelAfterImages  = "merge:3-after-images" // defined for shared label defs; PR-C omitted so unused in workflows
	mergeLabelAfterRelease = "merge:4-after-release"
)

func backportLabel(releaseBranch string) string {
	return fmt.Sprintf("backport-%s", releaseBranch)
}

func prAMainLabels(releaseBranch string) []string {
	return []string{labelRelease, "impact:critical", backportLabel(releaseBranch), labelSkipChangelog, labelTeamAutomation, mergeLabelFFDay}
}

func prBReleaseLabels() []string {
	return append(append([]string{}, ffReleasePRLabels...), mergeLabelAfterBranch)
}

func patchVersionBumpLabels() []string {
	return append(append([]string{}, releasePRLabels...), mergeLabelAfterRelease)
}

func checkRequirements(cfg *ReleaseConfig) error {
	parsed, err := parseSemver(cfg.CurrentRelease)
	if err != nil {
		return err
	}

	if (parsed.major == 6 || parsed.major == 7 || parsed.major == 8) && parsed.patch == 0 {
		return fmt.Errorf("minor releases for version %d.x are deprecated and blocked", parsed.major)
	}

	repo, err := openRepo(".")
	if err != nil {
		return err
	}

	clean, err := repo.isClean()
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory is not clean. Please commit or stash changes first")
	}

	return nil
}

type workflowPR struct {
	branch string
	base   string
	opts   prOptions
}

type workflowPRResult struct {
	item workflowPR
	pr   *github.PullRequest
}

// RunMajorMinorRelease executes the feature-freeze workflow:
// 1. Creates the release branch from BASE_BRANCH
// 2. Opens PR-A on main (backport rule + next minor version)
// 3. Opens PR-B on release branch (ensure CURRENT version)
//
// PR-C (main docs / test-env) is omitted: fleet-server has no docs or test-env
// version updates in the former fleet-server.mak process.
// Next-patch bumps are intentionally omitted here; they are created only by
// RunPatchRelease so patch and minor/FF stay independent.
func RunMajorMinorRelease(cfg *ReleaseConfig) error {
	println("=== Starting Major/Minor Release Workflow ===")

	if err := ensureLatestRelease(cfg); err != nil {
		return err
	}

	if err := validateReleaseConfig(cfg); err != nil {
		return err
	}

	if err := checkRequirements(cfg); err != nil {
		return err
	}

	repo, err := openRepo(".")
	if err != nil {
		return err
	}

	if err := ensureMajorMinorCurrentReleaseMatchesBase(repo, cfg); err != nil {
		return err
	}

	releaseBranch := cfg.ReleaseBranch

	printf("Creating release branch: %s\n", releaseBranch)
	if err := repo.ensureBranchFrom(cfg.BaseBranch, releaseBranch); err != nil {
		return err
	}

	prA, err := prepMainBackportAndVersion(repo, cfg)
	if err != nil {
		return err
	}
	prB, err := prepFFRelease(repo, cfg)
	if err != nil {
		return err
	}

	branchesToFinalize := []workflowPR{prA, prB}

	if cfg.DryRun {
		println("\nDRY RUN: Skipping push and PR creation")
		printf("Release branch prepared: %s\n", releaseBranch)
		for _, item := range branchesToFinalize {
			printf("Branch prepared: %s\n", item.branch)
		}
		println("Note: PR-C (main docs) is omitted for fleet-server (no docs/test-env updates)")
		warnEnsureReleaseIssueTracker(cfg, nil)
		return nil
	}

	if err := repo.checkoutBranch(releaseBranch); err != nil {
		return err
	}
	if err := repo.push("origin", cfg.GitHubToken); err != nil {
		return err
	}

	gh := newgitHubClient(cfg.GitHubToken)
	results, err := finalizeWorkflowPRs(repo, gh, cfg.GitHubToken, branchesToFinalize)
	if err != nil {
		return err
	}

	printf("\n=== Major/Minor Release Workflow Complete ===\n")
	printf("Release branch created: %s\n", releaseBranch)
	printWorkflowPRResults(results)
	println("\nNote: PR-C (main docs) is omitted for fleet-server (no docs/test-env updates)")

	warnEnsureReleaseIssueTracker(cfg, prsFromWorkflowResults(results))
	return nil
}

func prepMainBackportAndVersion(repo *gitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	branch := fmt.Sprintf("ff-prep-main-%s", cfg.CurrentRelease)
	printf("\n--- Preparing PR-A: backport rule + version %s on %s ---\n", cfg.NextProjectMinorVersion, cfg.BaseBranch)

	if err := repo.ensureBranchFrom(cfg.BaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateMergify(cfg.ReleaseBranch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateVersion(cfg.NextProjectMinorVersion); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("[Release][%s] Prepare main for %s and mergify backport-%s", cfg.CurrentRelease, cfg.NextProjectMinorVersion, cfg.ReleaseBranch)
	if _, err := repo.commitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.BaseBranch,
		opts: prOptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release][%s] Prepare main for %s and mergify backport-%s", cfg.CurrentRelease, cfg.NextProjectMinorVersion, cfg.ReleaseBranch),
			Head:      branch,
			Base:      cfg.BaseBranch,
			Body:      prAMainBody(cfg),
			Reviewers: cfg.ProjectReviewers,
			Labels:    prAMainLabels(cfg.ReleaseBranch),
		},
	}, nil
}

func prepFFRelease(repo *gitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	title := fmt.Sprintf("[Release][%s] ff-release: update versions %s", cfg.CurrentRelease, cfg.CurrentRelease)
	return prepReleaseBranchVersionPR(
		repo,
		cfg,
		fmt.Sprintf("ff-release-%s", cfg.CurrentRelease),
		fmt.Sprintf("\n--- Preparing PR-B: ff-release %s on %s ---\n", cfg.CurrentRelease, cfg.ReleaseBranch),
		title,
		prBReleaseBody(cfg),
		prBReleaseLabels(),
	)
}

// prepPatchVersionBump prepares the post-release version bump to CURRENT_RELEASE.
// Matches ingest-dev prepare-next-patch. Used only by RunPatchRelease.
func prepPatchVersionBump(repo *gitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	title := fmt.Sprintf("[Release][%s] Update version to %s", cfg.CurrentRelease, cfg.CurrentRelease)
	return prepReleaseBranchVersionPR(
		repo,
		cfg,
		fmt.Sprintf("update-version-%s", cfg.CurrentRelease),
		fmt.Sprintf("\n--- Preparing patch version bump to %s on %s ---\n", cfg.CurrentRelease, cfg.ReleaseBranch),
		title,
		patchVersionBumpBody(cfg),
		patchVersionBumpLabels(),
	)
}

// prepReleaseBranchVersionPR creates a branch from the release branch, bumps version.go,
// and returns the PR options for finalize.
func prepReleaseBranchVersionPR(repo *gitRepo, cfg *ReleaseConfig, branch, logLine, title, body string, labels []string) (workflowPR, error) {
	printf("%s", logLine)

	if err := repo.ensureBranchFrom(cfg.ReleaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateVersion(cfg.CurrentRelease); err != nil {
		return workflowPR{}, err
	}
	if _, err := repo.commitAll(title, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.ReleaseBranch,
		opts: prOptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     title,
			Head:      branch,
			Base:      cfg.ReleaseBranch,
			Body:      body,
			Reviewers: cfg.ProjectReviewers,
			Labels:    labels,
		},
	}, nil
}

func prAMainBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`## [Release][%s]

Prepares %s for the %s feature freeze.

- Adds Mergify backport rule for branch %s (label %s)
- Bumps version/version.go to %s (next minor)

**Merge:** before release branch work is finalized.
`, cfg.CurrentRelease, cfg.BaseBranch, cfg.CurrentRelease, cfg.ReleaseBranch, backportLabel(cfg.ReleaseBranch), cfg.NextProjectMinorVersion)
}

func prBReleaseBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`## [Release][%s]

Feature-freeze release branch updates for %s (version/version.go).

Fleet Server has no docs/test-env updates in this step.

**Merge:** as soon as the %s branch exists.
`, cfg.CurrentRelease, cfg.CurrentRelease, cfg.ReleaseBranch)
}

func patchVersionBumpBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`## [Release][%s]

Post-release version bump on %s to %s (ingest-dev prepare-next-patch).

- Bumps version/version.go to %s

**Merge:** after the patch release job opens this PR (merge promptly).
`, cfg.CurrentRelease, cfg.ReleaseBranch, cfg.CurrentRelease, cfg.CurrentRelease)
}

func ensureMajorMinorCurrentReleaseMatchesBase(repo *gitRepo, cfg *ReleaseConfig) error {
	base := cfg.BaseBranch
	if base == "" {
		base = "main"
	}
	if err := repo.ensureBranch(base); err != nil {
		return err
	}
	branchVersion, err := readFleetVersion()
	if err != nil {
		return err
	}
	if branchVersion != cfg.CurrentRelease {
		return fmt.Errorf(
			"CURRENT_RELEASE=%s does not match version on %s (%s in version/version.go); "+
				"set CURRENT_RELEASE to the version already on %s (the minor being feature-frozen)",
			cfg.CurrentRelease, base, branchVersion, base,
		)
	}
	printf("Verified CURRENT_RELEASE=%s matches %s on branch %s\n", cfg.CurrentRelease, branchVersion, base)
	return nil
}

// RunPatchRelease executes the post-release patch bump on an existing release branch.
// CURRENT_RELEASE is the version to land (NEW_VERSION from version-bump), matching
// ingest-dev prepare-next-patch. Docs stay off this path.
func RunPatchRelease(cfg *ReleaseConfig) error {
	println("=== Starting Patch Release Workflow ===")

	if err := validateReleaseConfig(cfg); err != nil {
		return err
	}

	if err := checkRequirements(cfg); err != nil {
		return err
	}

	repo, err := openRepo(".")
	if err != nil {
		return err
	}

	if cfg.ReleaseBranch == "" {
		parsed, err := devtools.ParseReleaseVersion(cfg.CurrentRelease)
		if err != nil {
			return err
		}
		cfg.ReleaseBranch = devtools.InferReleaseBranch(parsed)
	}

	if err := ensurePatchBranchReadyForBump(repo, cfg); err != nil {
		return err
	}

	prBump, err := prepPatchVersionBump(repo, cfg)
	if err != nil {
		return err
	}

	branchesToFinalize := []workflowPR{prBump}

	if cfg.DryRun {
		println("\nDRY RUN: Skipping push and PR creation")
		for _, item := range branchesToFinalize {
			printf("Branch prepared: %s\n", item.branch)
		}
		warnEnsureReleaseIssueTracker(cfg, nil)
		return nil
	}

	gh := newgitHubClient(cfg.GitHubToken)
	results, err := finalizeWorkflowPRs(repo, gh, cfg.GitHubToken, branchesToFinalize)
	if err != nil {
		return err
	}

	printf("\n=== Patch Release Workflow Complete ===\n")
	printWorkflowPRResults(results)

	warnEnsureReleaseIssueTracker(cfg, prsFromWorkflowResults(results))
	return nil
}

func ensurePatchBranchReadyForBump(repo *gitRepo, cfg *ReleaseConfig) error {
	parsed, err := devtools.ParseReleaseVersion(cfg.CurrentRelease)
	if err != nil {
		return err
	}
	prev := devtools.InferLatestRelease(parsed)
	if prev == "" {
		return fmt.Errorf(
			"prepare-next-patch requires CURRENT_RELEASE with patch > 0 (got %s)",
			cfg.CurrentRelease,
		)
	}
	cfg.LatestRelease = prev

	if err := repo.ensureBranch(cfg.ReleaseBranch); err != nil {
		return err
	}
	branchVersion, err := readFleetVersion()
	if err != nil {
		return err
	}
	if branchVersion == cfg.CurrentRelease {
		return fmt.Errorf(
			"CURRENT_RELEASE=%s is already on branch %s; nothing to bump",
			cfg.CurrentRelease, cfg.ReleaseBranch,
		)
	}
	if branchVersion != prev {
		return fmt.Errorf(
			"CURRENT_RELEASE=%s expects version %s on branch %s (got %s in version/version.go); "+
				"set CURRENT_RELEASE to the version to land (NEW_VERSION from version-bump)",
			cfg.CurrentRelease, prev, cfg.ReleaseBranch, branchVersion,
		)
	}
	printf("Verified branch %s is at %s; will bump to CURRENT_RELEASE=%s\n", cfg.ReleaseBranch, branchVersion, cfg.CurrentRelease)
	return nil
}

func finalizeWorkflowPRs(repo *gitRepo, gh *gitHubClient, token string, items []workflowPR) ([]workflowPRResult, error) {
	results := make([]workflowPRResult, 0, len(items))
	for i, item := range items {
		pr, err := finalizePR(repo, gh, token, item.branch, item.base, item.opts)
		if err != nil {
			return results, fmt.Errorf("failed to finalize PR %d/%d: %w", i+1, len(items), err)
		}
		results = append(results, workflowPRResult{item: item, pr: pr})
	}
	return results, nil
}

func printWorkflowPRResults(results []workflowPRResult) {
	for i, result := range results {
		println(formatWorkflowPRLine(i+1, result))
	}
}

func prsFromWorkflowResults(results []workflowPRResult) []*github.PullRequest {
	var prs []*github.PullRequest
	for _, result := range results {
		if result.pr != nil {
			prs = append(prs, result.pr)
		}
	}
	return prs
}

func formatWorkflowPRLine(index int, result workflowPRResult) string {
	if result.pr != nil {
		return fmt.Sprintf("PR %d: %s (%s)", index, result.pr.GetHTMLURL(), prDisplayState(result.pr))
	}
	return fmt.Sprintf(
		"PR %d: skipped (no related open/merged PR for %s → %s)",
		index, result.item.branch, result.item.base,
	)
}

// finalizePR pushes a branch when it has new commits and creates or reuses an open PR.
// When the branch has nothing new to push, it still resolves a related open or merged PR
// so workflow summaries always list every expected slot.
func finalizePR(repo *gitRepo, gh *gitHubClient, token, branchName, baseBranch string, opts prOptions) (*github.PullRequest, error) {
	if err := repo.checkoutBranch(branchName); err != nil {
		return nil, err
	}

	existingPR, found, err := gh.findOpenPR(opts.Owner, opts.Repo, opts.Head, opts.Base)
	if err != nil {
		return nil, err
	}
	if found {
		if err := gh.ensurePRLabels(opts.Owner, opts.Repo, existingPR.GetNumber(), opts.Labels); err != nil {
			return nil, err
		}
		return existingPR, nil
	}

	ahead, err := repo.hasCommitsAheadOf(baseBranch)
	if err != nil {
		return nil, err
	}
	if !ahead {
		printf("No new commits on %s compared to %s; skipping push and PR creation\n", branchName, baseBranch)
		related, found, err := gh.findRelatedPR(opts.Owner, opts.Repo, opts.Head, opts.Base, opts.Title)
		if err != nil {
			return nil, err
		}
		if found {
			printf("Related PR #%d (%s): %s\n", related.GetNumber(), prDisplayState(related), related.GetHTMLURL())
			return related, nil
		}
		return nil, nil
	}

	if err := repo.push("origin", token); err != nil {
		return nil, err
	}

	return gh.createPR(opts)
}
