#!/bin/bash

set -euox pipefail

source .buildkite/scripts/common.sh

if check_repofile_exist "fleet-server" "main" "Makefile"; then
    IS_BRANCH_AVAILABLE=true
else
    IS_BRANCH_AVAILABLE=false
fi
echo ${IS_BRANCH_AVAILABLE}