#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path
if [[ "${FIPS:-false}" == "true" ]]; then
    with_msft_go
else
    with_go
fi

with_mage

mage build:local
