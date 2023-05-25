#!/bin/bash

set -euox pipefail

source .buildkite/scripts/common.sh

with_go

make docker-release

if command -v tree >/dev/null 2>&1; then
    tree -d
else
    ls -l
fi