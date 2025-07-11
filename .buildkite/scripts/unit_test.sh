#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

if [[ ${FIPS:-false} == "true" && ${GO_DISTRO:-stdlib} == "microsoft" ]]; then
    with_msft_go
else
  with_go
fi

with_mage

echo "Starting the unit tests..."
mage test:unit test:junitReport
