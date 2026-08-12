#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_docker_compose

with_mage

echo "Starting the E2E tests..."
test_status=0
mage test:e2e || test_status=$?
mage test:junitReport
exit "$test_status"
