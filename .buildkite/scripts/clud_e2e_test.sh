#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_Terraform

.ci/scripts/install-docker-compose.sh

docker version  | grep -A 2 -E "^Client|^Server"

apt-get update && apt-get install docker-ce=5:24.0.1-1~ubuntu.22.04~jammy docker-ce-cli=5:24.0.1-1~ubuntu.22.04~jammy

docker version  | grep -A 2 -E "^Client|^Server"

USER=fleetserverci make test-cloude2e
