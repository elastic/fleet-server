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
### Benchmark for pull request
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
### Benchmark for the ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}
<details><summary>go bench output for ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}</summary>

\`\`\`bash

${BENCH}
\`\`\`

</details>
_EOF_
fi

if [[ ${TYPE} == "compare" ]]; then
    echo "Comparing go benchmarks"
    buildkite-agent artifact download "build/base.out" .
    buildkite-agent artifact download "build/next.out" .
    BENCH_BASE=base.out BENCH_NEXT=next.out make benchstat | tee build/compare.out
    BENCH_COMPARE=$(cat build/compare.out)
    buildkite-agent annotate --style 'success' --context "benchstat" --append << _EOF_
### Benchmark Result
<details><summary>Benchmark diff against base branch</summary>

\`\`\`bash

${BENCH_COMPARE}

\`\`\`

</details>
_EOF_
fi


