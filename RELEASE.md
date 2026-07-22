# Fleet Server Release Automation

Mage-based release workflows for Fleet Server, replacing the former ingest-dev
[`fleet-server.mak`](https://github.com/elastic/ingest-dev/blob/main/release_scripts/fleet-server.mak)
Makefile process. Process shape matches beats and elastic-agent (feature-freeze
and patch merge-timing labels); file updates stay limited to `version/version.go`
and `.mergify.yml`.

## Quick start

```bash
export PROJECT_OWNER="your-user"
export CURRENT_RELEASE="9.6.0"   # must already match version/version.go on main
export GITHUB_TOKEN=$(gh auth token)
export DRY_RUN=true

# Feature freeze
mage release:runMajorMinor

# Patch release on an existing release branch
export CURRENT_RELEASE="9.6.1"   # must already match version on the release branch
mage release:runPatch

go test ./dev-tools/mage/release/... -count=1
```

Use plain `X.Y.Z` semver for `CURRENT_RELEASE` (no `-test` or `-SNAPSHOT` suffixes).

## Feature freeze (`mage release:runMajorMinor`)

`CURRENT_RELEASE` is the version **already on** `main` (the line being frozen).

| Slot | Branch → base | Changes | Merge label |
|---|---|---|---|
| Release branch | `X.Y` from `main` | pushed | — |
| **PR-A** | `ff-prep-main-{CURRENT}` → `main` | Mergify backport + bump to next minor | `merge:1-ff-day` |
| **PR-B** | `ff-release-{CURRENT}` → `X.Y` | ensure `version.go` = CURRENT (often no-op) | `merge:2-after-branch` |
| **PR-C** | — | **omitted** (no docs/test-env) | — |
| **PR-D** | `ff-prep-next-patch-{NEXT}` → `X.Y` | bump to next patch | `merge:4-after-release` |

## Patch (`mage release:runPatch`)

`CURRENT_RELEASE` is the version **already on** the release branch.

| Slot | Branch → base | Changes | Merge label |
|---|---|---|---|
| **PR-A** | `patch-release-{CURRENT}` → `X.Y` | ensure version (often skipped; no docs) | `merge:1-before-build` |
| **PR-B** | `ff-prep-next-patch-{NEXT}` → `X.Y` | bump to next patch | `merge:4-after-release` |

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `CURRENT_RELEASE` | yes | — | Version already on base/release branch |
| `GITHUB_TOKEN` | yes (unless dry run) | — | GitHub API token |
| `DRY_RUN` | no | `false` | Only `true` enables dry run |
| `BASE_BRANCH` | no | `main` | Base branch for feature freeze |
| `PROJECT_OWNER` | no | `elastic` | GitHub owner |
| `PROJECT_REPO` | no | `fleet-server` | GitHub repository |
| `PROJECT_REVIEWERS` | no | `elastic/elastic-agent-control-plane` | PR reviewers |

Derived (not env-overridable): `NEXT_RELEASE` (patch+1), `NEXT_PROJECT_MINOR_VERSION` (minor+1), `RELEASE_BRANCH` (`X.Y`), `LATEST_RELEASE` (patch−1 or GitHub lookup).

## Files updated

- `version/version.go` — `DefaultVersion`
- `.mergify.yml` — backport rule (PR-A)

## Idempotency

| Step | Re-run behavior |
|---|---|
| `UpdateVersion` | No-op when version already matches |
| `UpdateMergify` | No-op when backport rule already exists |
| Branch creation | Reuses existing branch |
| `CommitAll` | Skips when worktree is clean |
| `CreatePR` | Returns existing open PR for same head/base |

## Package layout

```
dev-tools/mage/release/
├── cmd/fleet-release/   # nested-module CLI
├── go.mod / go.sum      # isolates go-git / go-github
├── config.go
├── release.go
├── mergify.go
├── workflows.go
├── git.go / github.go / issue.go / version.go
└── README.md
```

Root `mage release:*` targets invoke `go run -C dev-tools/mage/release ./cmd/fleet-release …`.

## Testing

```bash
cd dev-tools/mage/release && go test ./... -count=1
```

Discard local workflow changes after review with `git reset --hard HEAD`.
