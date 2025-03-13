#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

echo "Starting the unit tests..."
if [ ${FIPS} = "true" ]; then
    make test-unit-fips junit-report
else
    make test-unit junit-report
fi
