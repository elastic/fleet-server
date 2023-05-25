#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

with_go

with_Terraform

.ci/scripts/install-docker-compose.sh

USER=fleetserverci make test-cloude2e
