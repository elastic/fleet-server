#!/usr/bin/env bash

set -euo pipefail

FLEET_SERVER_VERSION=${1:?"Fleet Server version is needed"}
PLATFORMS=${PLATFORMS:-"darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64"}

PLATFORM_FILES=()
for p in $PLATFORMS; do
  os="${p%%/*}"
  arch="${p##*/}"

  case "$os/$arch" in
    darwin/arm64) arch="aarch64" ;;
    */amd64) arch="x86_64" ;;
  esac

  case "$os" in
    windows) ext="zip" ;;
    *) ext="tar.gz" ;;
  esac

  file="${os}-${arch}.${ext}"
  PLATFORM_FILES+=("$file")
done

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
        echo -e "${RED}!! ${file}: The file was not created.${NO_COLOR}"
        exit 1
    else
        echo -e "- ${file} ${GREEN}OK${NO_COLOR}"
    fi

    fileSha512="${file}.sha512"
    if [ ! -f "${fileSha512}" ]; then
        echo -e "${RED}!! ${fileSha512}: The file was not created.${NO_COLOR}"
        exit 1
    else
        echo -e "- ${file}.sha512 ${GREEN}OK${NO_COLOR}"
    fi
done
