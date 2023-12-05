#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

export TYPE=${1}
#export BRANCH="${BUILDKITE_BRANCH}"

if [[ ${TYPE} == "pr" ]]; then
    echo "Starting the go benchmark for the pull request"
    BENCH_BASE=next.out make benchmark
fi

if [[ ${TYPE} == "base" ]]; then
    echo "Starting the go benchmark for the pull request"
    BENCH_BASE=base.out make benchmark
fi

