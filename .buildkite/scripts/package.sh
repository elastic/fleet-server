#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

VERSION=$(awk '/const DefaultVersion/{print $NF}' version/version.go | tr -d '"')
WORKSPACE="$(pwd)"
PATH="${PATH}:${WORKSPACE}/bin"
HOME="${WORKSPACE}"
IS_BRANCH_AVAILABLE=${BUILDKITE_BRANCH}
PLATFORM_TYPE=$(uname -m)
MATRIX_PLATFORM="$1"
MATRIX_TYPE="$2"

if [[ ${BUILDKITE_BRANCH} == "main" && ${MATRIX_TYPE} == "staging" ]]; then
    echo "INFO: staging artifacts for the main branch are not required."
else
    PLATFORMS=""
    PACKAGES=""
    if [[ ${PLATFORM_TYPE} == "arm" || ${PLATFORM_TYPE} == "aarch64" ]]; then
        PLATFORMS="linux/arm64"
        PACKAGES="docker"
    fi

    if [[ ${MATRIX_TYPE} == "staging" ]]; then
        MAKEGOAL="release-manager-release"
    else
        MAKEGOAL="release-manager-snapshot"
    fi

    cd ${BASE_DIR}
    with_go

    install_packages=(
            "github.com/magefile/mage",
            "github.com/elastic/go-licenser",
            "golang.org/x/tools/cmd/goimports",
            "github.com/jstemmer/go-junit-report",
            "gotest.tools/gotestsum"
    )

    for pckg in "${install_packages}"; do
    go install ${pckg}@latest
    done

    make ${MAKEGOAL}
fi

if [[ ${BUILDKITE_BRANCH} == "main" && ${MATRIX_TYPE} == "staging" ]]; then
    echo "INFO: staging artifacts for the main branch are not required."
else
    if [[ ${MATRIX_TYPE} == "staging" ]]; then
        MAKEGOAL="release-manager-release"
    else
        MAKEGOAL="release-manager-snapshot"
    fi
    echo "uploading artifacts..."
fi