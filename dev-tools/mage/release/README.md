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

`DRY_RUN` does **not** exercise Buildkite reference clones or a real token push.
Before merging changes under `dev-tools/mage/release/`, run the ingest
**release smoke** (below).

## Buildkite ingest release smoke (pre-merge)

Pipeline: [observability-robots-ingest-release-smoke](https://buildkite.com/elastic/observability-robots-ingest-release-smoke)
on [`elastic/observability-robots`](https://github.com/elastic/observability-robots)
([tools/ingest-release-smoke](https://github.com/elastic/observability-robots/tree/main/tools/ingest-release-smoke)).

It clones this repo at a candidate SHA, seeds `release-smoke/base` on
`elastic/observability-robots` (never `main`), runs `mage release:runMajorMinor`
then `mage release:runPatch` with a Vault-minted `GITHUB_TOKEN`, then deletes
smoke branches/PRs/issues.

Create a build with:

```text
SOURCE_REPO=fleet-server
SOURCE_SHA=<pr-head-sha>
```

Optional: `SOURCE_OWNER` (default `elastic`), `WORKFLOWS` (default
`major-minor,patch`).

Details: [ingest-release-smoke README](https://github.com/elastic/observability-robots/blob/main/tools/ingest-release-smoke/README.md).

