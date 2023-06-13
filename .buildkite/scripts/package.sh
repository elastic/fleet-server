#!/bin/bash

set -euo pipefail

VERSION=$(awk '/const DefaultVersion/{print $NF}' /mnt/c/Temp/version.go | tr -d '"')
WORKSPACE="$(pwd)"
PATH="${PATH}:${WORKSPACE}/bin"
HOME="${WORKSPACE}"

#setEnvVar('IS_BRANCH_AVAILABLE', isBranchUnifiedReleaseAvailable(env.BRANCH_NAME))

echo {{matrix.platform}} {{matrix.type}}
echo "${WORKSPACE}, ${PATH}, ${HOME}"
