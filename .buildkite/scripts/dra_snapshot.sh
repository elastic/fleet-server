#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path
google_cloud_auth
download_mbp_packages_from_gcp_bucket "/build/distributions" "snapshot"
