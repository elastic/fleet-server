#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

echo "Checking gsutil command..."
if ! command -v gsutil &> /dev/null ; then
    echo "⚠️ gsutil is not installed"
    exit 1
fi

add_bin_path

with_go

with_mage

mage docker:release

google_cloud_auth

upload_packages_to_gcp_bucket "build/distributions/"

mage test:release

mage docker:image
