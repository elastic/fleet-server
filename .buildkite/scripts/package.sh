#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

#IS_BRANCH_AVAILABLE=${BUILDKITE_BRANCH}
PLATFORM_TYPE=$(uname -m)
#MATRIX_PLATFORM="$1"
MATRIX_TYPE="$1"

if [[ ${BUILDKITE_BRANCH} == "main" && ${MATRIX_TYPE} == "staging" ]]; then
    echo "INFO: staging artifacts for the main branch are not required."
else
    PLATFORMS=""
    PACKAGES=""
    if [[ ${PLATFORM_TYPE} == "arm" || ${PLATFORM_TYPE} == "aarch64" ]]; then
        PLATFORMS="linux/arm64"
        PACKAGES="docker"
    fi

    add_bin_path
    with_go
    with_mage

    if [[ ${MATRIX_TYPE} == "staging" ]]; then
        make release
    else
        make SNAPSHOT=true release
    fi
fi

if [[ ${BUILDKITE_BRANCH} == "main" && ${MATRIX_TYPE} == "staging" ]]; then
    echo "INFO: staging artifacts for the main branch are not required."
else
    upload_mbp_packages_to_gcp_bucket "build/distributions/" "${MATRIX_TYPE}"
fi