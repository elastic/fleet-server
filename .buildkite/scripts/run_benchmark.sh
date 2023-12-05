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
    git checkout ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}
    BENCH_BASE=base.out make benchmark
fi

if [[ ${TYPE} == "compare" ]]; then
    echo "Comparing go benchmarks"
    git checkout ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}
    buildkite-agent artifact download "base.out" .
    buildkite-agent artifact download "next.out" .
    BENCH_BASE=base.out BENCH_NEXT=next.out make benchstat | tee compare.out

    BENCH_NEXT=$(cat base.out)
    BENCH_COMPARE=$(cat compare.out)
    buildkite-agent annotate --style 'success' --context "benchstat" --append << _EOF_
    ### Benchmark Result
    <details><summary>Benchmark diff against base branch</summary>

    ```bash
    ${BENCH_COMPARE}
    ```
    </details>

    <details><summary>Benchmark result</summary>

    ```bash
    ${BENCH_NEXT}
    ```
    </details>
_EOF_
fi


