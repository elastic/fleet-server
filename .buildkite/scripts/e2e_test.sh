#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_docker_compose

with_mage

echo "Starting the E2E tests..."
mage -v test:e2e test:junitReport
