#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_docker_compose

with_mage

# STACK_BUILD_ID is the full pinned version from .env, e.g. 9.5.0-335b21fa-SNAPSHOT.
# It is used to pin ES and Kibana images to the exact build being tested.
STACK_BUILD_ID=$(grep "^ELASTICSEARCH_VERSION=" dev-tools/integration/.env | cut -d= -f2)
# STACK_VERSION strips the build hash for the oblt-cli StackVersion parameter, e.g. 9.5.0-SNAPSHOT.
if [[ "$STACK_BUILD_ID" == *SNAPSHOT* ]]; then
  STACK_VERSION=$(echo "$STACK_BUILD_ID" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)-SNAPSHOT
else
  STACK_VERSION=$(echo "$STACK_BUILD_ID" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

cleanup() {
  r=$?
  if [ -f cluster-info.json ]; then
    CLUSTER_NAME=$(jq -r '.ClusterName' cluster-info.json)
    if [ -n "${CLUSTER_NAME}" ] && [ "${CLUSTER_NAME}" != "null" ]; then
      echo "--- Deployment detected, running cleanup."
      oblt-cli cluster destroy --cluster-name "${CLUSTER_NAME}" --force || true
      rm -f secrets.env.sh cluster-info.json
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
  --parameter "ElasticAgentDockerImage=${DOCKER_IMAGE}:${DOCKER_IMAGE_TAG}" \
  --parameter "ElasticsearchDockerImage=docker.elastic.co/cloud-release/elasticsearch-cloud-ess:${STACK_BUILD_ID}" \
  --parameter "KibanaDockerImage=docker.elastic.co/cloud-release/kibana-cloud:${STACK_BUILD_ID}" \
  --parameter "ElasticTeam=elastic-agent-control-plane" \
  --parameter "ElasticProject=fleet-server-ci"

CLUSTER_NAME=$(jq -r '.ClusterName' cluster-info.json)
echo "Cluster: ${CLUSTER_NAME}"

# Load deployment credentials as env vars.
# oblt-cli exports: FLEET_URL, KIBANA_HOST, ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD, and others.
oblt-cli cluster secrets env \
  --cluster-name="${CLUSTER_NAME}" \
  --output-file=secrets.env.sh
set -a
# shellcheck source=/dev/null
source secrets.env.sh
set +a
rm -f secrets.env.sh

if [[ "${FLEET_URL:-}" == "" ]]; then
  message="FLEET_URL is empty, cloud e2e tests cannot be executed"
  if [[ "${CI:-}" == "true" ]]; then
    buildkite-agent annotate \
      "${message}" \
      --context "ctx-cloude2e-test" \
      --style "error"
  fi
  echo "${message}"
  exit 1
fi

echo "Fleet server: ${FLEET_URL}"

echo "--- Trigger cloud E2E test"
mage test:cloudE2ERun
