#!/bin/bash

set -euo pipefail

VERSION=$(awk '/const DefaultVersion/{print $NF}' version/version.go | tr -d '"')
WORKSPACE="$(pwd)"
PATH="${PATH}:${WORKSPACE}/bin"
HOME="${WORKSPACE}"

#setEnvVar('IS_BRANCH_AVAILABLE', isBranchUnifiedReleaseAvailable(env.BRANCH_NAME))
PLATFORM_TYPE=$(uname -m)
PLATFORMS=""
PACKAGES=""
if [[ ${PLATFORM_TYPE} == "arm" || ${PLATFORM_TYPE} == "aarch64" ]]; then
    PLATFORMS="linux/arm64"
    PACKAGES="docker"
fi

echo "Platform: '$1'"
echo "Type: '$2'"

echo ${VERSION}
echo ${PLATFORM_TYPE}
echo $(uname)