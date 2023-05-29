#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_Terraform

with_docker_compose

USER=fleetserverci make test-cloude2e
