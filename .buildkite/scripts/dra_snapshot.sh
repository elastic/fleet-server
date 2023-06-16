#!/bin/bash

set -euox pipefail

source .buildkite/scripts/common.sh

request=$(check_repofile_exist "fleet-server" "main" "Makefile")
if [[ ${request} ]]; then
    export IS_BRANCH_AVAILABLE=true
else
    export IS_BRANCH_AVAILABLE=false
fi

echo ${IS_BRANCH_AVAILABLE}