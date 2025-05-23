#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_Terraform

with_docker_compose

with_mage

cleanup() {
  r=$?
  echo "cleanup starting, previous command had exit status: ${r}"

  if [ -f dev-tools/cloud/terraform/.terraform.lock.hcl ] ; then
    echo "--- Deployment detected, running cleanup."
    mage -v test:cloudE2EDown
    echo "deployment cleanup exit status is $?"
  else
      echo "--- No deployment detected, skipping cleanup."
  fi
  exit $r
}
trap cleanup EXIT INT TERM

USER=fleetserverci mage docker:cover docker:customAgentImage docker:push test:cloudE2EUp
FLEET_SERVER_URL=$(terraform output --raw --state=dev-tools/cloud/terraform/terraform.tfstate fleet_url)
echo "Fleet server: \"${FLEET_SERVER_URL}\""
echo "Deployment ID: $(terraform output --raw --state=dev-tools/cloud/terraform/terraform.tfstate deployment_id)"

if [[ "${FLEET_SERVER_URL}" == "" ]]; then
    message="FLEET_SERVER_URL is empty, cloud e2e tests cannot be executed"
    if [[ "${CI}" == "true" ]]; then
        buildkite-agent annotate \
            "${message}" \
            --context "ctx-cloude2e-test" \
            --style "error"
    fi
    echo "${message}"
    exit 0
fi

echo "--- Trigger cloud E2E test"
mage -v test:cloudE2ERun
