#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

PLATFORM_TYPE=$(uname -m)
TYPE="$1"
readonly VERSION_QUALIFIER="${VERSION_QUALIFIER:-""}"

if [[ ${BUILDKITE_BRANCH} == "main" && ${TYPE} == "staging" && -z ${VERSION_QUALIFIER} ]]; then
    echo "INFO: staging artifacts for the main branch are not required."
    exit 0
fi

PLATFORMS=""
if [[ ${PLATFORM_TYPE} == "arm" || ${PLATFORM_TYPE} == "aarch64" ]]; then
    PLATFORMS="linux/arm64"
fi

add_bin_path

if [[ ${FIPS:-false} == "true" ]]; then
    with_msft_go
    if [[ ${PLATFORM_TYPE} == "arm" || ${PLATFORM_TYPE} == "aarch64" ]]; then
        export PLATFORMS="linux/arm64"
    else
        export PLATFORMS="linux/amd64"
    fi
else
    with_go
fi
with_mage

case "${TYPE}" in
    "snapshot")
        export SNAPSHOT=true
        make release
        ;;
    "staging")
        make release
        ;;
    *)
    echo "The option is unsupported yet"
    ;;
esac

google_cloud_auth
upload_mbp_packages_to_gcp_bucket "build/distributions/**/*" "${TYPE}"
