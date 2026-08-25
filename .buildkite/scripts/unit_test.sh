#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path
with_go
with_mage

echo "Starting the unit tests..."
test_status=0
mage test:unit || test_status=$?
mage test:junitReport
exit "$test_status"
