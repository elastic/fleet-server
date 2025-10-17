#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)/bin"
TMP_FOLDER_TEMPLATE_BASE="tmp.fleet-server"
REPO="fleet-server"
platform_type=$(uname | tr '[:upper:]' '[:lower:]')
hw_type="$(uname -m)"

check_platform_architeture() {
# for downloading the GVM and Terraform packages
  case "${hw_type}" in
   "x86_64")
        arch_type="amd64"
        ;;
    "aarch64")
        arch_type="arm64"
        ;;
    "arm64")
        arch_type="arm64"
        ;;
    *)
    echo "The current platform/OS type is unsupported yet"
    ;;
  esac
}

create_workspace() {
    if [[ ! -d "${WORKSPACE}" ]]; then
    mkdir -p ${WORKSPACE}
    fi
}

add_bin_path() {
    echo "Adding PATH to the environment variables..."
    create_workspace
    export PATH="${PATH}:${WORKSPACE}"
}

with_go() {
    echo "Setting up the Go environment..."
    create_workspace
    check_platform_architeture
    SETUP_GVM_VERSION=v0.5.2
    retry 5 curl -sL -o ${WORKSPACE}/gvm "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-${platform_type}-${arch_type}"
    chmod +x ${WORKSPACE}/gvm
    eval "$(gvm --url=https://go.dev/dl $(cat .go-version))"
    go version
    which go
    export PATH="${PATH}:$(go env GOPATH):$(go env GOPATH)/bin"
}

with_docker_compose() {
    echo "Setting up the Docker-compose environment..."
    create_workspace
    retry 5 curl -sSL -o ${WORKSPACE}/docker-compose "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-${platform_type}-${hw_type}"
    chmod +x ${WORKSPACE}/docker-compose
    docker-compose version
}

retry() {
    local retries=$1
    shift
    local count=0
    until "$@"; do
        exit=$?
        wait=$((2 ** count))
        count=$((count + 1))
        if [ $count -lt "$retries" ]; then
            >&2 echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
            sleep $wait
        else
            >&2 echo "Retry $count/$retries exited $exit, no more retries left."
            return $exit
        fi
    done
    return 0
}

docker_logout() {
    echo "Logging out from Docker..."
    docker logout ${DOCKER_REGISTRY}
}

with_Terraform() {
    echo "Setting up the Terraform environment..."
    local path_to_file="${WORKSPACE}/terraform.zip"
    create_workspace
    check_platform_architeture
    retry 5 curl -sSL -o ${path_to_file} "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_${platform_type}_${arch_type}.zip"
    unzip -q ${path_to_file} -d ${WORKSPACE}/
    rm ${path_to_file}
    chmod +x ${WORKSPACE}/terraform
    terraform version
}

upload_packages_to_gcp_bucket() {
    local pattern=${1}
    local baseUri="gs://${JOB_GCS_BUCKET}/${REPO}"
    local bucketUriCommit="${baseUri}/commits/${BUILDKITE_COMMIT}"
    local bucketUriDefault="${baseUri}/snapshots"

    if [[ ${BUILDKITE_PULL_REQUEST} != "false" ]]; then
        bucketUriDefault="${baseUri}/pull-requests/pr-${GITHUB_PR_NUMBER}"
    fi
    for bucketUri in "${bucketUriCommit}" "${bucketUriDefault}"; do
        gcloud storage cp --recursive --quiet ${pattern} "${bucketUri}"
    done
}

get_bucket_uri() {
    local type=${1}
    local baseUri="gs://${JOB_GCS_BUCKET}/jobs"
    if [[ ${type} == "snapshot" ]]; then
        local folder="commits"
    else
        local folder="${type}"
    fi
    bucketUri="${baseUri}/${folder}/${BUILDKITE_COMMIT}"
}

upload_mbp_packages_to_gcp_bucket() {
    local pattern=${1}
    local type=${2}
    get_bucket_uri "${type}"
    gcloud storage cp --recursive --quiet ${pattern} ${bucketUri}
}

download_mbp_packages_from_gcp_bucket() {
    local pattern=${1}
    local type=${2}
    mkdir -p ${WORKSPACE}/${pattern}
    get_bucket_uri "${type}"
    gcloud storage cp --recursive --quiet ${bucketUri}/* ${WORKSPACE}/${pattern}
}

with_mage() {
    create_workspace
    go install github.com/magefile/mage # uses go.mod implicitly
    mage -clean
    mage -version
    which mage
}

cleanup() {
    echo "Deleting temporary files..."
    rm -rf ${WORKSPACE}/${TMP_FOLDER_TEMPLATE_BASE}.*
    echo "Done."
}
