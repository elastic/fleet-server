#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_docker_compose

# Extract stack version from dev-tools/integration/.env.
# Mirrors the regex logic in the former terraform main.tf:
# ELASTICSEARCH_VERSION=9.5.0-<hash>-SNAPSHOT -> 9.5.0-SNAPSHOT
ES_VERSION=$(grep "^ELASTICSEARCH_VERSION=" dev-tools/integration/.env | cut -d= -f2)
if [[ "$ES_VERSION" == *SNAPSHOT* ]]; then
  STACK_VERSION=$(echo "$ES_VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)-SNAPSHOT
else
  STACK_VERSION=$(echo "$ES_VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

cleanup() {
  r=$?
  if [ -f cluster-info.json ]; then
    CLUSTER_NAME=$(jq -r '.ClusterName' cluster-info.json)
    if [ -n "${CLUSTER_NAME}" ] && [ "${CLUSTER_NAME}" != "null" ]; then
      echo "--- Deployment detected, running cleanup."
      oblt-cli cluster destroy --cluster-name "${CLUSTER_NAME}" --force || true
    fi
  else
    echo "--- No deployment detected, skipping cleanup."
  fi
  exit $r
}
trap cleanup EXIT INT TERM

USER=fleetserverci mage docker:cover docker:customAgentImage docker:push

echo "--- Provisioning cloud deployment (stack: ${STACK_VERSION})"
oblt-cli cluster create custom \
  --template ess-ea-it \
  --cluster-name-prefix fleet-server \
  --output-file="${PWD}/cluster-info.json" \
  --wait 20 \
  --parameter "StackVersion=${STACK_VERSION}" \
  --parameter "ExpireInHours=2" \
  --parameter "ElasticAgentDockerImage=${DOCKER_IMAGE}:${DOCKER_IMAGE_TAG}"

CLUSTER_NAME=$(jq -r '.ClusterName' cluster-info.json)
echo "Cluster: ${CLUSTER_NAME}"

# Load deployment credentials as env vars.
# oblt-cli exports vars with the prefixes: ELASTICSEARCH_*, KIBANA_*, FLEET_SERVER_*, INTEGRATIONS_SERVER_*
oblt-cli cluster secrets env \
  --cluster-name="${CLUSTER_NAME}" \
  --output-file=secrets.env.sh
set -a
# shellcheck source=/dev/null
source secrets.env.sh
set +a
rm -f secrets.env.sh

# Map oblt-cli output var names to the names expected by testing/cloude2e/cloude2e_test.go
export FLEET_SERVER_URL="${FLEET_SERVER_HOST:-}"
export KIBANA_URL="${KIBANA_HOST:-}"
export ELASTIC_USER="${ELASTICSEARCH_USERNAME:-}"
export ELASTIC_PASS="${ELASTICSEARCH_PASSWORD:-}"

if [[ "${FLEET_SERVER_URL}" == "" ]]; then
  message="FLEET_SERVER_URL is empty, cloud e2e tests cannot be executed"
  if [[ "${CI:-}" == "true" ]]; then
    buildkite-agent annotate \
      "${message}" \
      --context "ctx-cloude2e-test" \
      --style "error"
  fi
  echo "${message}"
  exit 1
fi

echo "Fleet server: ${FLEET_SERVER_URL}"

echo "--- Trigger cloud E2E test"
mage test:cloudE2ERun
