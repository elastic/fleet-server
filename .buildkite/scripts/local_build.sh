#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

# for debugging purposes
set -x

add_bin_path
with_go

set +x

make local