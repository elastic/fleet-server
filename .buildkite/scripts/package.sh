#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

readonly VERSION_QUALIFIER="${VERSION_QUALIFIER:-""}"

if [[ ${BUILDKITE_BRANCH} == "main" && ${TYPE} == "staging" && -z ${VERSION_QUALIFIER} ]]; then
    echo "INFO: staging artifacts for the main branch are not required."
    exit 0
fi

add_bin_path
with_go
with_mage

mage docker:release
upload_mbp_packages_to_gcp_bucket "build/distributions/**/*" "${TYPE}"
