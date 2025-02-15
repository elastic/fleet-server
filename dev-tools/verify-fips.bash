#!/bin/bash

# This script does some basic sanity checking to verify that the passed binary is FIPS complian

set -euo pipefail

ARTIFACT=${1:?"A binary must be specified"}

echo -e "Checking ${ARTIFACT} for FIPS compliance"

if [ ! -f "${ARTIFACT}" ]; then
    echo -e "${ARTIFACT} does not exit"
    exit 1
fi

goVersion=$(go version -m ${ARTIFACT})

if ! echo "${goVersion}" | grep -q "GOEXPERIMENT=systemcrypto"; then
    echo "Did not find GOEXPERIMENT=systemcrypto flag in binary version information."
    exit 1
fi

if ! echo "${goVersion}" | grep -e "-tags" | grep -q "requirefips"; then
    echo "Did not find requirefips build tag in binary version information."
    exit 1
fi


# Check if artifact has symbols so we can look for
if echo "${goVersion}" | grep -e "-ldflags=" | grep -q -v -e "-s"; then
    # did not find -s within the ldflags; artifact should have symbols
    goNM=$(go tool nm ${ARTIFACT})
    if ! echo "${goNM}" | grep -q "OpenSSL_version"; then # FIXME this fails; but if I remove the -q it works?
        echo "Did not find OpenSSL symbols"
        exit 1
    fi
fi

echo "Compliance checks passed!"
