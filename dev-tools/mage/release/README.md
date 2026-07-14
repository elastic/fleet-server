# Fleet Server release automation

Mage-based release workflows for Fleet Server, aligned with the former
[`release_scripts/fleet-server.mak`](https://github.com/elastic/ingest-dev/blob/main/release_scripts/fleet-server.mak)
process and the package layout used in beats and elastic-agent.

## Commands

| Mage command | Former Makefile target | Description |
|---|---|---|
| `mage release:runMajorMinor` | `prepare-major-minor-release` + `create-branch-major-minor-release` | Push release branch; open bump-main PR |
| `mage release:runNextRelease` | `prepare-next-release` + `create-prs-next-release` | Open next patch + backport PRs |
| `mage release:runPatch` | `prepare-patch-release` + `create-prs-patch-release` | Open patch version PR into release branch |
| `mage release:updateVersion <version>` | `update-version` | Update `version/version.go` only |
| `mage release:updateMergify <version>` | `update-mergify` | Append backport rule to `.mergify.yml` |

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `CURRENT_RELEASE` | yes | — | Release version (`X.Y.Z`) |
| `GITHUB_TOKEN` | yes (unless `DRY_RUN=true`) | — | Token for push and PR creation |
| `DRY_RUN` | no | `false` | Prepare branches locally without push/PR |
| `BASE_BRANCH` | no | `main` | Base branch for major/minor |
| `RELEASE_BRANCH` | no | inferred from `CURRENT_RELEASE` | Release branch (e.g. `9.6`) |
| `NEXT_RELEASE` | no | inferred patch+1 | Next patch version on release branch |
| `NEXT_PROJECT_MINOR_VERSION` | no | inferred minor+1 | Next minor version for main bump |
| `LATEST_RELEASE` | no | inferred patch-1 | Previous patch (patch workflow) |
| `PROJECT_OWNER` | no | `elastic` | GitHub owner |
| `PROJECT_REPO` | no | `fleet-server` | GitHub repository |
| `PROJECT_REVIEWERS` | no | `elastic/elastic-agent-control-plane` | PR reviewers |

## Files updated

- `version/version.go` — `DefaultVersion`
- `.mergify.yml` — backport rule (next-release workflow only)

Fleet Server has no K8s/docs manifest updates in the former Makefile process.

## Local testing

```bash
export PROJECT_OWNER="your-user"
export CURRENT_RELEASE="9.6.0"
export GITHUB_TOKEN=$(gh auth token)
export DRY_RUN=true

mage release:runMajorMinor
git diff

mage release:runNextRelease
git diff

export RELEASE_BRANCH="9.6"
export CURRENT_RELEASE="9.6.2"
mage release:runPatch
git diff

go test ./dev-tools/mage/release/... -count=1
```

Discard local changes after review with `git reset --hard HEAD`.

## Idempotency

Workflow steps are safe to re-run: existing branches are reused, empty commits are skipped, open PRs are rediscovered, and file updates no-op when already applied.
