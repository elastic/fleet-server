#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_docker_compose

with_mage

echo "Starting the integration tests..."
mage test:integration test:junitReport
