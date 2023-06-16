#!/bin/bash

set -euox pipefail

source .buildkite/scripts/common.sh

check_repofile_exist "fleet-server" "main" "Makefile"

if [[ check_repofile_exist "fleet-server" "main" "Makefile" ]]; then
    export IS_BRANCH_AVAILABLE=true
else
    export IS_BRANCH_AVAILABLE=false
fi

echo ${IS_BRANCH_AVAILABLE}