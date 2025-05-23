#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_mage

echo "Starting the unit tests..."
mage test:unit test:junitReport
