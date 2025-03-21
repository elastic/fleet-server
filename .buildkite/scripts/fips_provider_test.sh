#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_msft_go

echo "Starting the provider tests..."
FIPS=true make test-unit junit-report

