#!/usr/bin/env bash
#
# This script is executed by the DRA stage.
# It requires the below environment variables:
# - BRANCH, the project branch
# - PROJECT, the release manager project
# - TYPE, the type of release (snapshot or staging)
# - VERSION, the version (either a release or a snapshot)
# - FOLDER, the relative folder where the binaries are stored
# - OUTPUT_FILE, the file where the logs are stored.
# - VAULT_ADDR
# - VAULT_ROLE_ID
# - VAULT_SECRET_ID
#
# It uses env variables to help to run this script with a simpler jenkins
# pipeline call.
#

source .buildkite/scripts/common.sh

set -ueo pipefail

readonly TYPE=${TYPE:-snapshot}
readonly OUTPUT_FILE=${OUTPUT_FILE:-release-manager-report.out}

# set required permissions on artifacts and directory
cd ${WORKSPACE}
chmod -R a+r "$FOLDER"/*
chmod -R a+w "$FOLDER"

# ensure the latest image has been pulled
IMAGE=docker.elastic.co/infra/release-manager:latest
(retry 3 docker pull --quiet "${IMAGE}") || echo "Error pulling ${IMAGE} Docker image, we continue"
docker images --filter=reference=${IMAGE}

# Generate checksum files and upload to GCS

run_release_manager() {
    echo "+++ Generate checksum files and upload to GCS..."
    local dry_run=""
    if [ "$BUILDKITE_PULL_REQUEST" != "false" ]; then
        dry_run="--dry-run"
    fi
    docker run --rm \
    --name release-manager \
    -e VAULT_ADDR="${VAULT_ADDR_SECRET}" \
    -e VAULT_ROLE_ID="${VAULT_ROLE_ID_SECRET}" \
    -e VAULT_SECRET_ID="${VAULT_SECRET}" \
    --mount type=bind,readonly=false,src="$PWD",target=/artifacts \
    "$IMAGE" \
      cli collect \
        --project "${PROJECT}" \
        --branch "${BRANCH}" \
        --commit "$(git rev-parse HEAD)" \
        --workflow "${TYPE}" \
        --artifact-set main \
        --version "${RM_VERSION}" \
        $dry_run 2>&1 | tee "$OUTPUT_FILE" \
        #
}

run_release_manager

RM_EXIT_CODE=$?

exit $RM_EXIT_CODE
