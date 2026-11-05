# Fleet Server release package

Operator reference for `dev-tools/mage/release/`. Release managers should start with [`RELEASE.md`](../../../RELEASE.md) at the repository root.

## Mage targets

| Target | CLI command | Purpose |
|---|---|---|
| `mage release:ensureIssueTracker` | `ensure-issue-tracker` | Create/update release checklist issue |
| `mage release:runMajorMinor` | `run-major-minor` | Feature freeze: release branch + PR-A/B (no next-patch) |
| `mage release:runPatch` | `run-patch` | Patch: post-release bump to `CURRENT_RELEASE` |
| `mage release:updateMergify` | `update-mergify` | Append backport rule |
| `mage release:updateVersion` | `update-version` | Update `version/version.go` only |

There is **no** `runNextRelease` target; version bumps after a patch release are opened only by `runPatch` (not `runMajorMinor`).

## Architecture

- Nested Go module keeps `go-git` / `go-github` out of the root `go.mod` / `NOTICE.txt`.
- Root mage wrappers call `go run -C dev-tools/mage/release ./cmd/fleet-release …` with `FLEET_SERVER_REPO_ROOT` set.
- File allowlist: only `version/version.go` and `.mergify.yml`.

## Alignment with beats / elastic-agent

Shared process: merge-timing labels, idempotent branches/PRs, issue tracker, nested module.
Patch `CURRENT_RELEASE` is the version to land (`NEW_VERSION`); the release branch must already be at the previous patch.

Fleet Server differences (from former `fleet-server.mak`):

- No K8s / Helm / docs / test-env updates → **PR-C omitted**
- Patch opens a single version bump PR (no docs PR)

## Local testing

```bash
export PROJECT_OWNER="$USER"
export CURRENT_RELEASE="$(grep DefaultVersion version/version.go | sed -E 's/.*"([^"]+)".*/\1/')"
export DRY_RUN=true
export GITHUB_TOKEN="$(gh auth token)"

mage release:runMajorMinor
```
