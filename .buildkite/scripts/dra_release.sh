#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

VERSION="$(awk '/const DefaultVersion/{print $NF}' version/version.go | tr -d '"')"
FOLDER_PATH="build/distributions"
BASE_DIR="${WORKSPACE}/${FOLDER_PATH}"
DRA_OUTPUT="release-manager.out"
PROJECT="fleet-server"
TYPE=${1}
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

download_mbp_packages_from_gcp_bucket "${FOLDER_PATH}" "${TYPE}"

with_go

with_mage

if [[ "${TYPE}" == "snapshot" ]]; then
    SNAPSHOT=true
fi

mkdir -p ${BASE_DIR}/reports
./dev-tools/dependencies-report --csv ${BASE_DIR}/reports/dependencies-${VERSION}.csv
cd ${BASE_DIR}/reports && shasum -a 512 dependencies-${VERSION}.csv > dependencies-${VERSION}.csv.sha512

echo "test run before running the ./scripts/release-manager.sh script" #TODO - chould be chaged to "./scripts/release-manager.sh" after the aprooval
