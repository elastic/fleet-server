// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ReleaseConfig holds configuration for release operations.
type ReleaseConfig struct {
	Version       string
	BaseBranch    string
	ReleaseBranch string
	Owner         string
	Repo          string
	AuthorName    string
	AuthorEmail   string
}

// LoadReleaseConfigFromEnv loads release configuration from environment variables.
func LoadReleaseConfigFromEnv() (*ReleaseConfig, error) {
	version := os.Getenv("CURRENT_RELEASE")
	if version == "" {
		return nil, fmt.Errorf("CURRENT_RELEASE environment variable not set")
	}

	baseBranch := os.Getenv("BASE_BRANCH")
	if baseBranch == "" {
		baseBranch = "main"
	}

	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid version format: %s (expected X.Y.Z)", version)
	}
	releaseBranch := fmt.Sprintf("%s.%s", parts[0], parts[1])

	owner := os.Getenv("PROJECT_OWNER")
	if owner == "" {
		owner = "elastic"
	}

	repo := os.Getenv("PROJECT_REPO")
	if repo == "" {
		repo = "fleet-server"
	}

	authorName := os.Getenv("GITHUB_USERNAME")
	if authorName == "" {
		authorName = "elasticmachine"
	}

	authorEmail := os.Getenv("GITHUB_EMAIL")
	if authorEmail == "" {
		authorEmail = "infra-root+elasticmachine@elastic.co"
	}

	return &ReleaseConfig{
		Version:       version,
		BaseBranch:    baseBranch,
		ReleaseBranch: releaseBranch,
		Owner:         owner,
		Repo:          repo,
		AuthorName:    authorName,
		AuthorEmail:   authorEmail,
	}, nil
}

// UpdateVersion updates the version in version/version.go.
func UpdateVersion(newVersion string) error {
	versionFile := "version/version.go"

	content, err := os.ReadFile(versionFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", versionFile, err)
	}

	re := regexp.MustCompile(`(const\s+DefaultVersion\s*=\s*)"[^"]+"`)
	contentStr := string(content)
	alreadyAtVersion := regexp.MustCompile(`const\s+DefaultVersion\s*=\s*"` + regexp.QuoteMeta(newVersion) + `"`)
	if alreadyAtVersion.MatchString(contentStr) {
		fmt.Printf("  Version already set to %s in %s\n", newVersion, versionFile)
		return nil
	}

	newContent := re.ReplaceAllString(contentStr, `${1}"`+newVersion+`"`)

	if newContent == contentStr {
		return fmt.Errorf("version pattern not found in %s", versionFile)
	}

	err = os.WriteFile(versionFile, []byte(newContent), 0o644)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", versionFile, err)
	}

	fmt.Printf("✓ Updated version to %s in %s\n", newVersion, versionFile)
	return nil
}

// UpdateMergify adds a new backport rule to .mergify.yml.
func UpdateMergify(version string) error {
	mergifyFile := ".mergify.yml"

	content, err := os.ReadFile(mergifyFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", mergifyFile, err)
	}

	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid version format: %s (expected X.Y.Z)", version)
	}
	branchVersion := fmt.Sprintf("%s.%s", parts[0], parts[1])

	searchPattern := fmt.Sprintf("backport patches to %s branch", branchVersion)
	if strings.Contains(string(content), searchPattern) {
		fmt.Printf("  Backport rule for %s already exists\n", branchVersion)
		return nil
	}

	newRule := fmt.Sprintf(`  - name: backport patches to %s branch
    conditions:
      - merged
      - label=backport-%s
    actions:
      backport:
        branches:
          - "%s"
`, branchVersion, branchVersion, branchVersion)

	output := string(content) + newRule

	err = os.WriteFile(mergifyFile, []byte(output), 0o644)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", mergifyFile, err)
	}

	fmt.Printf("✓ Added backport rule for %s to %s\n", branchVersion, mergifyFile)
	return nil
}

// PrepareMajorMinorRelease prepares files for a major/minor release.
func PrepareMajorMinorRelease(cfg *ReleaseConfig) error {
	fmt.Printf("Preparing major/minor release for version %s\n", cfg.Version)

	if err := UpdateVersion(cfg.Version); err != nil {
		return err
	}

	if err := UpdateMergify(cfg.Version); err != nil {
		return err
	}

	fmt.Println("✓ Major/minor release preparation complete")
	fmt.Printf("  Next steps:\n")
	fmt.Printf("  1. Review changes: git diff\n")
	fmt.Printf("  2. Create branch: mage release:createBranch\n")
	fmt.Printf("  3. Create PR: mage release:createPR\n")

	return nil
}

// CreateReleaseBranch creates a release branch with all changes committed.
func CreateReleaseBranch(cfg *ReleaseConfig, repoPath string, dryRun bool) error {
	repo, err := OpenRepo(repoPath)
	if err != nil {
		return err
	}

	branchName := cfg.ReleaseBranch
	fmt.Printf("Creating release branch: %s\n", branchName)

	if !dryRun {
		if err := repo.CreateBranch(branchName); err != nil {
			return err
		}

		commitMsg := fmt.Sprintf("[Release] Prepare %s release", cfg.Version)
		if err := repo.CommitAll(commitMsg, cfg.AuthorName, cfg.AuthorEmail); err != nil {
			return err
		}
	} else {
		fmt.Printf("  [DRY RUN] Would create branch %s and commit changes\n", branchName)
	}

	return repo.Push("origin", dryRun)
}

// CreateReleasePR creates a pull request for the release.
func CreateReleasePR(cfg *ReleaseConfig, ghClient *GitHubClient, dryRun bool) error {
	title := fmt.Sprintf("[Release] %s", cfg.Version)
	body := fmt.Sprintf("## Release %s\n\nThis PR prepares the %s release.\n\n### Changes\n- Updated version to %s\n- Added mergify backport rule for %s\n",
		cfg.Version, cfg.Version, cfg.Version, cfg.ReleaseBranch)

	_, err := ghClient.CreatePR(PROptions{
		Owner: cfg.Owner,
		Repo:  cfg.Repo,
		Title: title,
		Head:  cfg.ReleaseBranch,
		Base:  cfg.BaseBranch,
		Body:  body,
	}, dryRun)
	return err
}

// RunMajorMinorRelease orchestrates the complete major/minor release workflow.
func RunMajorMinorRelease(cfg *ReleaseConfig, dryRun bool) error {
	if dryRun {
		fmt.Println("🔍 DRY RUN MODE - No changes will be pushed")
	}

	fmt.Printf("🚀 Starting major/minor release workflow for %s\n\n", cfg.Version)

	fmt.Println("Step 1: Preparing release files...")
	if err := PrepareMajorMinorRelease(cfg); err != nil {
		return fmt.Errorf("failed to prepare release: %w", err)
	}

	fmt.Println("\nStep 2: Creating release branch...")
	if err := CreateReleaseBranch(cfg, ".", dryRun); err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	fmt.Println("\nStep 3: Creating pull request...")
	ghClient, err := NewGitHubClientFromEnv()
	if err != nil {
		return err
	}
	if err := CreateReleasePR(cfg, ghClient, dryRun); err != nil {
		return fmt.Errorf("failed to create PR: %w", err)
	}

	fmt.Printf("\n✅ Major/minor release workflow complete for %s\n", cfg.Version)
	return nil
}

// PreparePatchRelease prepares files for a patch release.
func PreparePatchRelease(cfg *ReleaseConfig) error {
	fmt.Printf("Preparing patch release for version %s\n", cfg.Version)

	if err := UpdateVersion(cfg.Version); err != nil {
		return err
	}

	fmt.Println("✓ Patch release preparation complete")
	return nil
}

// RunPatchRelease orchestrates the complete patch release workflow.
func RunPatchRelease(cfg *ReleaseConfig, dryRun bool) error {
	if dryRun {
		fmt.Println("🔍 DRY RUN MODE - No changes will be pushed")
	}

	fmt.Printf("🚀 Starting patch release workflow for %s\n\n", cfg.Version)

	fmt.Println("Preparing patch release files...")
	if err := PreparePatchRelease(cfg); err != nil {
		return fmt.Errorf("failed to prepare patch release: %w", err)
	}

	fmt.Printf("\n✅ Patch release workflow complete for %s\n", cfg.Version)
	fmt.Println("  Review changes and commit to the release branch")
	return nil
}

// PrepareNextRelease prepares files for the next development cycle.
func PrepareNextRelease(currentVersion string) error {
	parts := strings.Split(currentVersion, ".")
	if len(parts) < 3 {
		return fmt.Errorf("invalid version format: %s", currentVersion)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid minor version: %s", parts[1])
	}

	nextVersion := fmt.Sprintf("%s.%d.0", parts[0], minor+1)

	fmt.Printf("Preparing next development cycle: %s -> %s\n", currentVersion, nextVersion)

	if err := UpdateVersion(nextVersion); err != nil {
		return err
	}

	fmt.Printf("✓ Next release preparation complete: %s\n", nextVersion)
	return nil
}
