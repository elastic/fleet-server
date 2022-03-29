#!/usr/bin/env bash

set -euo pipefail

FLEET_SERVER_VERSION=${1:?"Fleet Server version is needed"}

PLATFORM_FILES=(darwin-aarch64.tar.gz darwin-x86_64.tar.gz linux-arm64.tar.gz linux-x86_64.tar.gz linux-x86.tar.gz windows-x86_64.zip windows-x86.zip)

#make release

FILE_PREFIX="build/distributions/fleet-server-${FLEET_SERVER_VERSION}-"

RED='\033[0;31m'
GREEN='\033[0;32m'
NO_COLOR='\033[0m'

echo -e "Checking fleet-server-${FLEET_SERVER_VERSION} binaries created after a release:"

for PLATFORM_FILE in "${PLATFORM_FILES[@]}"
do
    file="${FILE_PREFIX}${PLATFORM_FILE}"
    if [ ! -f "${file}" ]; then
        echo -e "${RED}!! ${PLATFORM_FILE}: The file was not created.${NO_COLOR}"
        exit 1
    else
        echo -e "- ${PLATFORM_FILE} ${GREEN}OK${NO_COLOR}"
    fi

    fileSha512="${file}.sha512"
    if [ ! -f "${fileSha512}" ]; then
        echo -e "${RED}!! ${fileSha512}: The file was not created.${NO_COLOR}"
        exit 1
    else
        echo -e "- ${PLATFORM_FILE}.sha512 ${GREEN}OK${NO_COLOR}"
    fi
done
