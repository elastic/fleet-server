#!/bin/bash

set -euox pipefail

source .buildkite/scripts/common.sh

check_repofile_exist "fleet-server" "main" "Makefile"

echo ${IS_BRANCH_AVAILABLE}