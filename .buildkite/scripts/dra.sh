#!/bin/bash
##
##  Generates and uploads the DRA prep sub-pipeline for a single workflow
##  (snapshot or staging), replacing the previous Release Manager Docker step.
##
##  Relies on .buildkite/hooks/pre-command for tooling setup, and on the
##  pipeline's own `if:` gates (FILE_EXISTS_IN_REPO) to only run on active
##  release branches -- this script does not re-check branch activity.
##

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path
with_go
with_mage

readonly TYPE="${1:-snapshot}"

VERSION="$(mage getVersion)"

if [[ "${VERSION}" == "" ]]; then
    echo "The 'version' parameter is required."
    exit 1
fi

if [[ "${TYPE}" == "staging" && "${VERSION}" == *"-SNAPSHOT"* ]]; then
    echo "VERSION unexpectedly contains '-SNAPSHOT' for a staging build: ${VERSION}"
    exit 1
fi

# Dry run enabled skips annotation and uploads.
DRA_UPLOAD=true
if [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
    DRA_UPLOAD=false
fi

echo "--- :arrow_right: DRA context"
echo "BUILDKITE_BRANCH=${BUILDKITE_BRANCH}"
echo "BUILDKITE_COMMIT=${BUILDKITE_COMMIT}"
echo "TYPE=${TYPE}"
echo "VERSION=${VERSION}"
echo "DRA_UPLOAD=${DRA_UPLOAD}"

annotate_step=""
trigger_step=""
if [[ "${DRA_UPLOAD}" == "true" ]]; then
  annotate_step=$(cat <<ANN

  - label: ":memo: Annotate DRA summary (${TYPE})"
    key: "dra-annotate-${TYPE}"
    depends_on: "dra-prep-${TYPE}"
    command: ".buildkite/scripts/dra-annotate.sh ${TYPE}"
    agents:
      provider: "gcp"
      image: "${IMAGE_UBUNTU_X86_64}"
    timeout_in_minutes: 5
ANN
)
  trigger_step=$(cat <<TRIG

  - label: ":pipeline: DRA processing for fleet-server (${TYPE})"
    trigger: "unified-release-dra-processing"
    depends_on: "dra-prep-${TYPE}"
    build:
      env:
        DRA_PRODUCT_ID: "fleet-server"
        DRA_STACK_VERSION: "${VERSION}"
        DRA_WORKFLOW: "${TYPE}"
TRIG
)
fi

echo "--- Generating DRA sub-pipeline for ${TYPE} (upload=${DRA_UPLOAD})"
cat <<PIPELINE | buildkite-agent pipeline upload
steps:
  - label: ":package: DRA Prep (${TYPE})"
    key: "dra-prep-${TYPE}"
    command: ".buildkite/scripts/stage-dra-artifacts.sh"
    env:
      DRA_WORKFLOW: "${TYPE}"
      VERSION_QUALIFIER: "${VERSION_QUALIFIER:-}"
    agents:
      provider: "gcp"
      image: "${IMAGE_UBUNTU_X86_64}"
      machineType: "c2-standard-16"
    timeout_in_minutes: 30
    artifact_paths:
      - "artifacts/dra/fleet-server/*/manifest-*.json"
    plugins:
      - elastic/oblt-google-auth#v1.2.0:
          lifetime: 10800 # seconds
          project-id: "elastic-observability-ci"
          project-number: "911195782929"
      - elastic/dra-prep#v0.1.6:
          product_id: "fleet-server"
          stack_version: "${VERSION}"
          workflow: "${TYPE}"
          upload: ${DRA_UPLOAD}
${annotate_step}
${trigger_step}
PIPELINE
