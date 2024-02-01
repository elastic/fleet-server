#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  r=$?

  echo "--- Cleaning deployment"
  make -C "${CLOUD_TESTING_BASE}" cloud-clean

  exit $r
}
trap cleanup EXIT INT TERM


echo "--- Creating deployment"
make -C "${CLOUD_TESTING_BASE}" cloud-deploy

# Ensure Fleet server URL is defined to run the tests
FLEET_SERVER_URL=$(make --no-print-directory -C "${CLOUD_TESTING_BASE}" cloud-get-fleet-url)
echo "Fleet server: \"${FLEET_SERVER_URL}\""
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
make test-cloude2e-set | tee build/test-cloude2e-set

