#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_msft_go

echo "Starting the provider enabled tests..."
make test-fips-provider-unit junit-report

