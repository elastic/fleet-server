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

  if [ -f dev-tools/cloud/terraform/.terraform.lock.hcl ] ; then
    echo "--- Cleaning deployment"
    mage test:cloudE2EDown
  else
      echo "Skipped cleaning deployment, no Terraform files"
  fi
  exit $r
}

USER=fleetserverci mage -v docker:cover docker:customAgentImage docker:push test:cloudE2EUp
FLEET_SERVER_URL=$(terraform output --raw --state=dev-tools/cloud/terraform/terraform.tfstate fleet_url)
echo "Fleet server: \"${FLEET_SERVER_URL}\""
echo "Integrations URL: $(terraform output --raw --state=dev-tools/cloud/terraform/terraform.tfstate integrations_url)"

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
mage test:cloudE2ERun | tee build/test-cloude2e-set
