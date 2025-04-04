#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

echo "Starting the unit tests..."
make test-unit junit-report
