#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_docker_compose

echo "Starting the integration tests..."
make test-int junit-report
