#!/usr/bin/env bash
##
##  Downloads packaged binaries for this workflow from the GCS bucket used by
##  fleet-server's package steps, generates the dependency CSV report, and
##  stages both into artifacts/ for the elastic/dra-prep plugin.
##
##  The GCS bucket layout already separates snapshot and staging artifacts by
##  workflow (see common.sh:get_bucket_uri), so no filename-based filtering is
##  needed here -- everything downloaded for this WORKFLOW belongs to it.
##

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path
with_go
with_mage

WORKFLOW="${DRA_WORKFLOW:?DRA_WORKFLOW is required}"
FOLDER_PATH="build/distributions"
BASE_DIR="${WORKSPACE}/${FOLDER_PATH}"
VERSION="$(mage getVersion)"

echo "--- Downloading ${WORKFLOW} packages from GCS"
download_mbp_packages_from_gcp_bucket "${FOLDER_PATH}" "${WORKFLOW}"

echo "--- Generating dependency report"
mkdir -p "${BASE_DIR}/reports"
./dev-tools/dependencies-report --csv "${BASE_DIR}/reports/dependencies-${VERSION}.csv"
(cd "${BASE_DIR}/reports" && shasum -a 512 "dependencies-${VERSION}.csv" > "dependencies-${VERSION}.csv.sha512")

echo "--- Staging ${WORKFLOW} artifacts"
chmod -R a+r "${BASE_DIR}"/*
chmod -R a+w "${BASE_DIR}"
mkdir -p artifacts
find "${BASE_DIR}" -maxdepth 1 -type f -exec cp {} artifacts/ \;
find "${BASE_DIR}/reports" -maxdepth 1 -type f -exec cp {} artifacts/ \;

if ! ls artifacts/* >/dev/null 2>&1; then
  echo "ERROR: no ${WORKFLOW} artifacts found in artifacts/" >&2
  exit 1
fi

echo "Staged artifacts:"
ls -1 artifacts/
