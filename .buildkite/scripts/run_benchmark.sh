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
    BENCH=$(cat build/next.out)
    buildkite-agent annotate --style 'success' --context "gobench_pr" --append << _EOF_
#### Benchmark for pull request
<details><summary>go bench output</summary>

\`\`\`bash

${BENCH}
\`\`\`

</details>
_EOF_
fi

if [[ ${TYPE} == "base" ]]; then
    echo "Starting the go benchmark for the pull request"
    git checkout ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}
    BENCH_BASE=base.out make benchmark
    BENCH=$(cat build/base.out)
    buildkite-agent annotate --style 'success' --context "gobench_base" --append << _EOF_
#### Benchmark for the ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}
<details><summary>go bench output for ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}</summary>

\`\`\`bash

${BENCH}
\`\`\`

</details>
_EOF_
fi

if [[ ${TYPE} == "compare" ]]; then
    echo "Comparing go benchmarks"
    go install go.bobheadxi.dev/gobenchdata@latest
    buildkite-agent artifact download "build/base.out" .
    buildkite-agent artifact download "build/next.out" .

    cat build/base.out| gobenchdata --json build/base.json
    cat build/next.out| gobenchdata --json build/next.json
    gobenchdata checks eval build/base.json build/next.json --json build/full_report.json
    status=$(jq -r '.Status' build/full_report.json)
    if [[ $status == "fail" ]]; then
      cat build/full_report.json| jq 'del(.Checks."My Check".Diffs[]| select(.Status == "pass") )'| tee build/failed_report.json
      gobenchdata checks report failed.json | tee build/failed_summary.md
      BENCH_COMPARE=$(cat build/failed_summary.md)
      buildkite-agent annotate --style 'error' --context "benchstat" --append << _EOF_
#### Benchmark comparison
<details><summary>Comparison table of benchmark results of HEAD compared to ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}</summary>

${BENCH_COMPARE}

</details>
_EOF_
    else
      BENCH_COMPARE=$(gobenchdata checks report build/full_report.json)
      buildkite-agent annotate --style 'success' --context "benchstat" --append << _EOF_
#### Benchmark comparison
<details><summary>No significant performance issue detect against ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}</summary>

${BENCH_COMPARE}

</details>
_EOF_
    fi
fi


