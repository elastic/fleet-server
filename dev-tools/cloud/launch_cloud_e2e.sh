#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  r=$?

  make -C ${CLOUD_TESTING_BASE} cloud-clean

  exit $r
}
trap cleanup EXIT INT TERM


make -C ${CLOUD_TESTING_BASE} cloud-deploy

# Fleet server URL is obtained in "test-cloude2e-set" target
# FLEET_SERVER_URL=$(make --no-print-directory -C ${CLOUD_TESTING_BASE} cloud-get-fleet-url)
# export FLEET_SERVER_URL

make test-cloude2e-set | tee build/test-cloude2e-set

