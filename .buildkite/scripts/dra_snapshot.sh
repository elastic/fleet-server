#!/bin/bash

set -euox pipefail

source .buildkite/scripts/common.sh

google_cloud_auth

download_mbp_packages_from_gcp_bucket "/build/distributions" "snapshot"
