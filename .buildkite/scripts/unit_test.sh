#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path

with_go

with_mage

echo "Starting the unit tests..."
<<<<<<< HEAD
if [[ ${FIPS:-} == "true" ]]; then
    make test-unit-fips junit-report
else
    make test-unit junit-report
fi
=======
mage test:unit test:junitReport
>>>>>>> db5f46b (Convert Makefile to magefile.go (#4912))
