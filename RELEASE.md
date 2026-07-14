# Fleet-Server Release Automation

Mage-based release workflows for Fleet Server, replacing the former ingest-dev
[`fleet-server.mak`](https://github.com/elastic/ingest-dev/blob/main/release_scripts/fleet-server.mak)
Makefile process. Package layout matches beats and elastic-agent under
`dev-tools/mage/release/`.

## Quick start

```bash
export PROJECT_OWNER="your-user"
export CURRENT_RELEASE="9.6.0"
export GITHUB_TOKEN=$(gh auth token)
export DRY_RUN=true

# Major/minor after feature freeze
mage release:runMajorMinor

# Next patch + backport PRs (run after runMajorMinor)
mage release:runNextRelease

# Patch release on an existing release branch
export RELEASE_BRANCH="9.6"
export CURRENT_RELEASE="9.6.2"
mage release:runPatch

git diff
go test ./dev-tools/mage/release/... -count=1
```

Use plain `X.Y.Z` semver for `CURRENT_RELEASE` (no `-test` or `-SNAPSHOT` suffixes).

## Workflow alignment

| Former (ingest-dev) | Mage command | PRs produced |
|---|---|---|
| `prepare-major-minor-release` + `create-branch-major-minor-release` | `mage release:runMajorMinor` | Push release branch; PR `bump-version-<next-minor>` → `main` |
| `prepare-next-release` + `create-prs-next-release` | `mage release:runNextRelease` | PR `update-version-next-<patch>` → release branch; PR `add-backport-next-<next-minor>` → `main` |
| `prepare-patch-release` + `create-prs-patch-release` | `mage release:runPatch` | PR `update-docs-version-<version>` → release branch |

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `CURRENT_RELEASE` | yes | — | Version to release (`9.6.0`) |
| `GITHUB_TOKEN` | yes (unless dry run) | — | GitHub API token |
| `DRY_RUN` | no | `false` | Prepare branches locally without push/PR |
| `BASE_BRANCH` | no | `main` | Base branch for major/minor |
| `RELEASE_BRANCH` | no | inferred | Release branch (e.g. `9.6`) |
| `NEXT_RELEASE` | no | patch+1 | Next patch on release branch |
| `NEXT_PROJECT_MINOR_VERSION` | no | minor+1 | Next minor for main bump |
| `PROJECT_OWNER` | no | `elastic` | GitHub owner |
| `PROJECT_REPO` | no | `fleet-server` | GitHub repository |
| `PROJECT_REVIEWERS` | no | `elastic/elastic-agent-control-plane` | PR reviewers |

## Files updated

- `version/version.go` — `DefaultVersion`
- `.mergify.yml` — backport rule (next-release workflow)

## Idempotency

Release steps are safe to re-run after partial failure or CI retry:

| Step | Re-run behavior |
|---|---|
| `UpdateVersion` | No-op when version already matches |
| `UpdateMergify` | No-op when backport rule already exists |
| Branch creation | Reuses existing branch |
| `CommitAll` | Skips when worktree is clean |
| `Push` | Succeeds when remote is up to date |
| `CreatePR` | Returns existing open PR for same head/base |

## Package layout

```
dev-tools/mage/release/
├── config.go       # Env loading and version inference
├── release.go      # UpdateVersion
├── mergify.go      # UpdateMergify
├── workflows.go    # RunMajorMinor, RunNextRelease, RunPatch
├── git.go          # Branch, commit, push helpers
├── github.go       # PR creation and labels
└── README.md       # Maintainer reference
```

See `dev-tools/mage/release/README.md` for detailed command mapping.

## Testing

```bash
cd dev-tools && go test ./mage/release/... -count=1
```

Discard local workflow changes after review with `git reset --hard HEAD`.
