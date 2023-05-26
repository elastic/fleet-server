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

make docker-release

google_cloud_auth

gsutil ls gs://${JOB_GCS_BUCKET}
pwd
ls -l
