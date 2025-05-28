#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_mage

echo "Starting the fips140=only unit tests..."
mage test:unitFIPSOnly test:junitReport
