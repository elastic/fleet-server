#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

echo "Checking gcloud command..."
if ! command -v gcloud &> /dev/null ; then
    echo "⚠️ gcloud is not installed"
    exit 1
fi

add_bin_path

with_go

with_mage

mage docker:release

upload_packages_to_gcp_bucket "build/distributions/"

mage test:release

mage docker:image
