#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_docker_compose

echo "Starting the E2E tests..."
make test-e2e junit-report
