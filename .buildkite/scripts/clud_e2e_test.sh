#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

#START TEST PART
echo "TESTVAR1 = ${TESTVAR1}"
echo "TESTVAR1 = $${TESTVAR1}"

echo "TESTVAR2 = ${TESTVAR2}"
echo "TESTVAR2 = $${TESTVAR2}"
echo "TESTVAR2_SECRET = ${TESTVAR2_SECRET}"
echo "TESTVAR2_SECRET = $${TESTVAR2_SECRET}"

echo "TESTVAR3 = ${TESTVAR3}"
echo "TESTVAR3 = $${TESTVAR3}"

#END TEST PART


add_bin_path

with_go

with_Terraform

.ci/scripts/install-docker-compose.sh

USER=fleetserverci make test-cloude2e
