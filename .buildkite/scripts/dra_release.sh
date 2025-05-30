#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_mage

FOLDER_PATH="build/distributions"
BASE_DIR="${WORKSPACE}/${FOLDER_PATH}"
DRA_OUTPUT="release-manager.out"
export PROJECT="fleet-server"
export TYPE=${1}
# DRA_BRANCH can be used for manually testing packaging with PRs
# e.g. define `DRA_BRANCH="main"` under Options/Environment Variables in the Buildkite UI after clicking new Build
export BRANCH="${DRA_BRANCH:="${BUILDKITE_BRANCH:=""}"}"
export VERSION="$(mage getVersion)"

if [[ "${VERSION}" == *"-SNAPSHOT"* || "${VERSION}" == "" ]]; then
    echo "The 'version' parameter is required and it cannot contain the suffix '-SNAPSHOT'."
    exit 1
fi

if [[ "${PROJECT}" == "" ]]; then
    echo "The 'project' parameter is required."
    exit 1
fi

download_mbp_packages_from_gcp_bucket "${FOLDER_PATH}" "${TYPE}"
export RM_VERSION="${VERSION}"

if [[ ${TYPE} == "snapshot" ]]; then
    export SNAPSHOT=true
    VERSION="${VERSION}-SNAPSHOT"
fi

mkdir -p ${BASE_DIR}/reports
./dev-tools/dependencies-report --csv ${BASE_DIR}/reports/dependencies-${VERSION}.csv
cd ${BASE_DIR}/reports && shasum -a 512 dependencies-${VERSION}.csv > dependencies-${VERSION}.csv.sha512

cd $(dirname ${WORKSPACE})
export FOLDER="${FOLDER_PATH}"
export OUTPUT_FILE="${DRA_OUTPUT}"
./.buildkite/scripts/release-manager.sh          #TODO use "echo" for rollback
