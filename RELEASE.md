# Fleet-Server Release Automation

This document describes the fleet-server release automation implemented using Mage, following the architecture patterns established in elastic-agent.

## Quick Start

### Prerequisites

- Go 1.25+
- Mage installed (`go install github.com/magefile/mage@latest`)
- GitHub token with repo permissions
- Clean git working directory

### Major/Minor Release (e.g., 9.5.0)

```bash
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token"
export DRY_RUN=true

# Test first (updates files locally, no push/PR)
mage release:runMajorMinor

# Review changes
git status
git diff

# Run for real
export DRY_RUN=false
mage release:runMajorMinor
```

### Patch Release (e.g., 9.4.1)

```bash
# Checkout base branch
git checkout 9.4
git pull

export CURRENT_RELEASE="9.4.1"
export BASE_BRANCH="9.4"
export GITHUB_TOKEN="ghp_your_token"

mage release:runPatch
```

## Available Commands

### Orchestration Commands (Recommended)

These commands run the full release workflow:

- `mage release:runMajorMinor` - Complete major/minor release workflow
- `mage release:runPatch` - Complete patch release workflow

### Individual Commands

For manual control or debugging:

- `mage release:updateVersion <version>` - Update version in version/version.go
- `mage release:updateMergify <version>` - Add backport rule to .mergify.yml
- `mage release:prepareMajorMinor` - Prepare all files for major/minor release
- `mage release:preparePatch` - Prepare files for patch release
- `mage release:prepareNext` - Prepare next development cycle
- `mage release:createBranch` - Create and push release branch
- `mage release:createPR` - Create GitHub pull request

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `CURRENT_RELEASE` | Version to release | `9.5.0` |
| `GITHUB_TOKEN` | GitHub API token | `ghp_xxx` |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `DRY_RUN` | Test mode (no push/PR) | `false` |
| `BASE_BRANCH` | Base branch for PR | `main` |
| `PROJECT_OWNER` | GitHub repository owner | `elastic` |
| `PROJECT_REPO` | GitHub repository name | `fleet-server` |
| `GITHUB_USERNAME` | Git commit author name | `elasticmachine` |
| `GITHUB_EMAIL` | Git commit author email | `infra-root+elasticmachine@elastic.co` |

## Workflows

### Major/Minor Release Workflow

The `runMajorMinor` command performs these steps:

1. **Prepare Files**
   - Updates `version/version.go` with new version
   - Adds backport rule to `.mergify.yml`

2. **Create Branch**
   - Creates release branch (e.g., `9.5`)
   - Commits all changes
   - Pushes to remote (unless DRY_RUN=true)

3. **Create PR**
   - Creates pull request from release branch to main
   - Includes version update details
   - (Skipped if DRY_RUN=true)

### Patch Release Workflow

The `runPatch` command performs these steps:

1. **Prepare Files**
   - Updates `version/version.go` with patch version

2. **Commit & Review**
   - Changes are prepared for manual review
   - No automatic branch creation
   - Commit to the current release branch manually

### Next Development Cycle

The `prepareNext` command:

- Increments minor version (e.g., 9.4.0 → 9.5.0)
- Updates `version/version.go`
- Used after a release to bump version on main

## DRY_RUN Mode

DRY_RUN mode allows you to test the release process safely:

```bash
export DRY_RUN=true
mage release:runMajorMinor
```

**What DRY_RUN does:**
- ✅ Updates local files (version/version.go, .mergify.yml)
- ✅ Shows what would be committed
- ❌ Does NOT create branches
- ❌ Does NOT push to remote
- ❌ Does NOT create pull requests

**After DRY_RUN:**
- Review changes with `git diff`
- Discard changes with `git checkout .`
- Or proceed with `DRY_RUN=false`

## Testing on a Fork

Before using the release automation in production, it's **highly recommended** to test on your personal fork first. This allows you to verify the workflow end-to-end without affecting the official repository.

### Step 1: Fork and Clone

1. Fork the fleet-server repository on GitHub to your account
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/fleet-server.git
   cd fleet-server
   ```

3. Ensure you're on a clean main branch:
   ```bash
   git checkout main
   git pull origin main
   ```

### Step 2: Configure Environment

Set environment variables to point to your fork:

```bash
# Point to your fork
export PROJECT_OWNER="your-username"
export PROJECT_REPO="fleet-server"

# Use a test version to avoid confusion
export CURRENT_RELEASE="9.5.0-test"

# Your GitHub personal access token
export GITHUB_TOKEN="ghp_your_token"

# Important: Set to false to actually create branches and PRs
export DRY_RUN=false
```

### Step 3: Run the Workflow

Execute the major/minor release workflow:

```bash
mage release:runMajorMinor
```

This will:
- Update `version/version.go` to `9.5.0-test`
- Add backport rule for `9.5` to `.mergify.yml`
- Create branch `9.5` on your fork
- Push the branch to your fork
- Create a PR from `9.5` → `main` on your fork

### Step 4: Verify the Results

Check what was created:

```bash
# View the created branch
git branch -a | grep 9.5

# View the created PR
gh pr list --repo YOUR-USERNAME/fleet-server
```

Or visit GitHub: `https://github.com/YOUR-USERNAME/fleet-server/pulls`

### Step 5: Review and Clean Up

1. Review the PR on your fork to ensure:
   - Version was updated correctly
   - Mergify rule was added properly
   - Commit message is appropriate

2. If satisfied, close the PR and delete the test branch:
   ```bash
   gh pr close BRANCH-NUMBER --repo YOUR-USERNAME/fleet-server --delete-branch
   ```

3. Reset your fork's main branch:
   ```bash
   git checkout main
   git reset --hard origin/main
   ```

### Testing Different Scenarios

#### Test Patch Release on Fork

```bash
export PROJECT_OWNER="your-username"
export CURRENT_RELEASE="9.4.1-test"
export BASE_BRANCH="9.4"
export GITHUB_TOKEN="ghp_your_token"

# Create the release branch first if it doesn't exist
git checkout -b 9.4
git push -u origin 9.4

# Run patch workflow
mage release:runPatch
```

#### Test with DRY_RUN First

For extra safety, test with DRY_RUN before creating real branches:

```bash
export PROJECT_OWNER="your-username"
export DRY_RUN=true
mage release:runMajorMinor

# Review local changes
git diff

# If satisfied, run for real
export DRY_RUN=false
mage release:runMajorMinor
```

### Troubleshooting Fork Testing

**Issue: "failed to push: authentication required"**
- Ensure your GITHUB_TOKEN has write access to your fork
- Verify: `gh auth status`

**Issue: "branch already exists"**
- Delete the existing branch first:
  ```bash
  git branch -D 9.5
  git push origin --delete 9.5
  ```

**Issue: "PR already exists"**
- Close or merge the existing PR first
- Or use a different version number (e.g., `9.5.0-test2`)

### Best Practices

1. **Always test on fork first** before running in production
2. **Use test version numbers** (e.g., `X.Y.Z-test`) to distinguish from real releases
3. **Clean up test branches and PRs** after testing to keep your fork tidy
4. **Test both workflows**: major/minor AND patch releases
5. **Verify DRY_RUN mode** works correctly before relying on it

## Troubleshooting

### "CURRENT_RELEASE environment variable not set"

Set the required environment variable:
```bash
export CURRENT_RELEASE="9.5.0"
```

### "GITHUB_TOKEN environment variable not set"

Set your GitHub token:
```bash
export GITHUB_TOKEN=$(gh auth token)
```

Or create a personal access token at: https://github.com/settings/tokens

### "failed to open git repo"

Ensure you're in the fleet-server repository root:
```bash
cd /path/to/fleet-server
```

### "version pattern not found"

The version file format has changed. Check that `version/version.go` contains:
```go
const DefaultVersion = "X.Y.Z"
```

### Uncommitted changes warning

The workflow warns about uncommitted files but continues. To avoid confusion:
```bash
git status
git stash  # or commit your changes
```

## Architecture

Fleet-server follows the same architecture as elastic-agent but is simpler:

**Key Differences from elastic-agent:**
- Fewer files to update (only 1: `version/version.go`)
- No docs/K8s manifest updates needed
- All code in `magefile.go` (no separate package)
- Simpler implementation (~540 lines vs ~2000+ in elastic-agent)

**Libraries used:**
- `github.com/go-git/go-git/v5` - Git operations
- `github.com/google/go-github/v68` - GitHub API
- `gopkg.in/yaml.v3` - YAML parsing (already present)

**No external tools:**
- ❌ No `hub` CLI
- ❌ No `gh` CLI
- ❌ No `sed` / `awk`
- ❌ No `yq`
- ✅ Pure Go implementation

## Examples

### Complete Major/Minor Release

```bash
# 1. Start on main branch
git checkout main
git pull

# 2. Set up environment
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN=$(gh auth token)

# 3. Test with dry run
export DRY_RUN=true
mage release:runMajorMinor

# 4. Review changes
git diff version/version.go
git diff .mergify.yml

# 5. Run for real
export DRY_RUN=false
mage release:runMajorMinor

# 6. Check the PR that was created
gh pr list
```

### Patch Release on Existing Branch

```bash
# 1. Checkout release branch
git checkout 9.4
git pull

# 2. Set up environment
export CURRENT_RELEASE="9.4.1"
export BASE_BRANCH="9.4"
export GITHUB_TOKEN=$(gh auth token)

# 3. Run patch workflow
mage release:runPatch

# 4. Review and commit
git diff
git add version/version.go
git commit -m "Bump version to 9.4.1"
git push
```

### Bump Version After Release

```bash
# 1. After 9.5.0 release, bump main to 9.6.0
git checkout main

# 2. Run next version prep
export CURRENT_RELEASE="9.5.0"
mage release:prepareNext

# 3. Commit the change
git add version/version.go
git commit -m "Bump version to 9.6.0"
git push
```

## Testing

Run unit tests for release functions:

```bash
go test -v -tags=mage -run "TestUpdate|TestLoad|TestPrepare" .
```

Check test coverage:

```bash
go test -v -tags=mage -coverprofile=coverage.out .
go tool cover -func=coverage.out | grep -E "(UpdateVersion|UpdateMergify)"
```

## Migration from Makefile

This replaces the old Makefile-based release process:

| Old (Makefile) | New (Mage) |
|----------------|------------|
| `make prepare-major-minor-release` | `mage release:runMajorMinor` |
| `make prepare-patch-release` | `mage release:runPatch` |
| `make update-version VERSION=9.5.0` | `mage release:updateVersion 9.5.0` |
| `make prepare-next-release` | `mage release:prepareNext` |

**Benefits of Mage:**
- Pure Go (no sed, hub, Python dependencies)
- Type-safe with compile-time checks
- Built-in DRY_RUN mode
- Better error messages
- Easier to test and maintain

## Support

- **Issues**: https://github.com/elastic/fleet-server/issues
- **Documentation**: This file and migration plan
- **Code**: `magefile.go` (search for "Release Automation")

---

**Last Updated**: 2026-03-12
