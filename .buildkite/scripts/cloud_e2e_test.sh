#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_Terraform

with_docker_compose

with_mage

# tf_output prints the named terraform output, or nothing when it cannot be
# read. Never fails, so it is safe to use under set -e.
tf_output() {
  terraform output --raw "--state=dev-tools/cloud/terraform/terraform.tfstate" "$1" 2>/dev/null || true
}

cleanup() {
  r=$?

  if [ -f dev-tools/cloud/terraform/.terraform.lock.hcl ] ; then
    echo "--- Deployment detected, running cleanup."
    mage test:cloudE2EDown
  else
      echo "--- No deployment detected, skipping cleanup."
  fi
  exit $r
}
trap cleanup EXIT INT TERM

USER=fleetserverci mage docker:cover docker:customAgentImage docker:push

# test:cloudE2EUp provisions the deployment and then waits for it to actually
# be usable - the fleet endpoint published, Kibana and fleet-server serving.
# Elastic Cloud reports a deployment as created well before that is true.
echo "--- Provision the cloud deployment and wait for it to be ready"
if ! USER=fleetserverci mage test:cloudE2EUp; then
    message="cloud deployment did not become ready, cloud e2e tests cannot be executed"
    if [[ "${CI}" == "true" ]]; then
        buildkite-agent annotate \
            "${message}" \
            --context "ctx-cloude2e-test" \
            --style "error"
    fi
    echo "${message}"
    exit 1
fi

echo "Fleet server: \"$(tf_output fleet_url)\""
echo "Deployment ID: $(tf_output deployment_id)"

echo "--- Trigger cloud E2E test"
mage test:cloudE2ERun
