#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

VERSION="$(awk '/const DefaultVersion/{print $NF}' version/version.go | tr -d '"')"
BASE_DIR="${WORKSPACE}/${FOLDER}"
DRA_OUTPUT="release-manager.out"
PROJECT="fleet-server"
TYPE="snapshot"
FOLDER="build/distributions"
BRANCH="${BUILDKITE_BRANCH}"

if [[ "${VERSION}" == *"-SNAPSHOT"* || "${VERSION}" == "" ]]; then
    echo "The 'version' parameter is required and it cannot contain the suffix '-SNAPSHOT'."
    exit 1
fi

if [[ "${PROJECT}" == "" ]]; then
    echo "The 'project' parameter is required."
    exit 1
fi


add_bin_path

google_cloud_auth

download_mbp_packages_from_gcp_bucket "${FOLDER}" "${TYPE}"

with_go

with_mage

SNAPSHOT=true

mkdir -p ${BASE_DIR}/reports
./dev-tools/dependencies-report --csv ${BASE_DIR}/reports/dependencies-${VERSION}.csv
cd ${BASE_DIR}/reports && shasum -a 512 dependencies-${VERSION}.csv > dependencies-${VERSION}.csv.sha512

echo "test run before running the ./scripts/release-manager.sh script"
