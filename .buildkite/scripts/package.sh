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
PACKAGES=""
if [[ ${PLATFORM_TYPE} == "arm" || ${PLATFORM_TYPE} == "aarch64" ]]; then
    PLATFORMS="linux/arm64"
    PACKAGES="docker"
fi

add_bin_path
with_go
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
