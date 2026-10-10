# Fleet Server release package

Operator reference for `dev-tools/mage/release/`. Release managers should start with [`RELEASE.md`](../../../RELEASE.md) at the repository root.

## Mage targets

| Target | CLI command | Purpose |
|---|---|---|
| `mage release:runMajorMinor` | `run-major-minor` | Feature freeze: release branch + PR-A/B/D |
| `mage release:runPatch` | `run-patch` | Patch: PR-A (often skipped) + next-patch PR-B |
| `mage release:updateVersion` | `update-version` | Update `version/version.go` only |
| `mage release:updateMergify` | `update-mergify` | Append backport rule |
| `mage release:ensureIssueTracker` | `ensure-issue-tracker` | Create/update release checklist issue |

There is **no** `runNextRelease` target; next-patch prep is PR-D inside `runMajorMinor` / PR-B inside `runPatch`.

## Architecture

- Nested Go module keeps `go-git` / `go-github` out of the root `go.mod` / `NOTICE.txt`.
- Root mage wrappers call `go run -C dev-tools/mage/release ./cmd/fleet-release …` with `FLEET_SERVER_REPO_ROOT` set.
- File allowlist: only `version/version.go` and `.mergify.yml`.

## Alignment with beats / elastic-agent

Shared process: `CURRENT_RELEASE` must match `version.go`, merge-timing labels, idempotent branches/PRs, issue tracker, nested module.

Fleet Server differences (from former `fleet-server.mak`):

- No K8s / Helm / docs / test-env updates → **PR-C omitted**
- Patch “docs” PR has no doc files → often skipped when version already matches

## Local testing

```bash
export PROJECT_OWNER="$USER"
export CURRENT_RELEASE="$(grep DefaultVersion version/version.go | sed -E 's/.*"([^"]+)".*/\1/')"
export DRY_RUN=true
export GITHUB_TOKEN="$(gh auth token)"

mage release:runMajorMinor
```
