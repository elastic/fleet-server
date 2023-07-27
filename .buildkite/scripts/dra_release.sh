#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

FOLDER_PATH="build/distributions"
BASE_DIR="${WORKSPACE}/${FOLDER_PATH}"
DRA_OUTPUT="release-manager.out"
export PROJECT="fleet-server"
export TYPE=${1}
export BRANCH="${BUILDKITE_BRANCH}"
export VERSION="$(make get-version)"

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


if [[ ${TYPE} == "snapshot" ]]; then
    export SNAPSHOT=true
fi

mkdir -p ${BASE_DIR}/reports
./dev-tools/dependencies-report --csv ${BASE_DIR}/reports/dependencies-${VERSION}.csv
cd ${BASE_DIR}/reports && shasum -a 512 dependencies-${VERSION}.csv > dependencies-${VERSION}.csv.sha512

cd ${WORKSPACE}
export FOLDER="${FOLDER_PATH}"
export OUTPUT_FILE="${DRA_OUTPUT}"
echo "$(pwd)"
ls -la
./.buildkite/scripts/release-manager.sh          #TODO use "echo" for rollback
