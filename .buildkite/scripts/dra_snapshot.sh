#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

VERSION="$(awk '/const DefaultVersion/{print $NF}' version/version.go | tr -d '"')"
BASE_DIR="${WORKSPACE}/build/distributions"

add_bin_path

google_cloud_auth

download_mbp_packages_from_gcp_bucket "/build/distributions/" "snapshot"

with_go

SNAPSHOT=true
mkdir -p ${BASE_DIR}/reports
./dev-tools/dependencies-report --csv ${BASE_DIR}/reports/dependencies-${VERSION}.csv
cd ${BASE_DIR}/reports && shasum -a 512 dependencies-${VERSION}.csv > dependencies-${VERSION}.csv.sha512
