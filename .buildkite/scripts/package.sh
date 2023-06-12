#!/bin/bash

set -euo pipefail

VERSION=$(shell awk '/const DefaultVersion/{print $$NF}' version/version.go | tr -d '"')
WORKSPACE="$(pwd)"
PATH="${PATH}:${WORKSPACE}/bin"
HOME="${WORKSPACE}"

#setEnvVar('IS_BRANCH_AVAILABLE', isBranchUnifiedReleaseAvailable(env.BRANCH_NAME))

echo {{matrix.platform}} {{matrix.type}}
