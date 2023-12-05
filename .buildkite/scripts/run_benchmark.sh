#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

echo "Starting the go benchmark for the pull request"
BENCH_BASE=next.out make benchmark

#TODO
#echo "Starting the go benchmark for the base branch"
#BENCH_BASE=base.out make benchmark
