#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)/bin"
TMP_FOLDER_TEMPLATE_BASE="tmp.fleet-server"
REPO="fleet-server"

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
    retry 5 curl -sL -o ${WORKSPACE}/gvm "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-linux-amd64"
    chmod +x ${WORKSPACE}/gvm
    eval "$(gvm $(cat .go-version))"
    go version
    which go
    export PATH="${PATH}:$(go env GOPATH):$(go env GOPATH)/bin"
}

with_docker_compose() {
    echo "Setting up the Docker-compose environment..."
    create_workspace
    retry 5 curl -SL -o ${WORKSPACE}/docker-compose "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64"
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

publish_docker_image() {
    echo "Pushing the docker image "$DOCKER_IMAGE":"$DOCKER_IMAGE_TAG" to the "${DOCKER_REGISTRY}" registry..."
    DOCKER_IMAGE=${DOCKER_IMAGE} DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG} make release-docker
}

docker_logout() {
    echo "Logging out from Docker..."
    docker logout ${DOCKER_REGISTRY}
}

with_Terraform() {
    echo "Setting up the Terraform environment..."
    destFile="terraform.zip"
    create_workspace
    retry 5 curl -SL -o ${WORKSPACE}/${destFile} "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
    unzip -q ${WORKSPACE}/${destFile} -d ${WORKSPACE}/
    rm ${WORKSPACE}/${destFile}
    chmod +x ${WORKSPACE}/terraform
    terraform version
}

google_cloud_auth() {
    secretFileLocation=$(mktemp -d -p "${WORKSPACE}" -t "${TMP_FOLDER_TEMPLATE_BASE}.XXXXXXXXX")/google-cloud-credentials.json
    echo "${PRIVATE_CI_GCS_CREDENTIALS_SECRET}" > ${secretFileLocation}
    gcloud auth activate-service-account --key-file ${secretFileLocation} 2> /dev/null
    export GOOGLE_APPLICATIONS_CREDENTIALS=${secretFileLocation}
}

upload_packages_to_gcp_bucket() {
    pattern=${1}
    baseUri="gs://${JOB_GCS_BUCKET}/${REPO}/buildkite"              #TODO: needs to delete the "/buildkite" part after the migration from Jenkins
    bucketUriCommit="${baseUri}"/commits/${BUILDKITE_COMMIT}
    bucketUriDefault="${baseUri}"/snapshots

    if [[ ${BUILDKITE_PULL_REQUEST} != "false" ]]; then
        bucketUriDefault="${baseUri}"/pull-requests/pr-${GITHUB_PR_NUMBER}
    fi

    for bucketUri in "${bucketUriCommit}" "${bucketUriDefault}"; do
        gsutil -m -q cp -a public-read -r ${pattern} "${bucketUri}"
    done
}

get_bucket_uri() {
    local type=${1}
    local baseUri="gs://${JOB_GCS_BUCKET}/jobs/buildkite"
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
    gsutil -m -q cp -a public-read -r ${pattern} ${bucketUri}
}

download_mbp_packages_from_gcp_bucket() {
    local pattern=${1}
    local type=${2}
    mkdir -p ${WORKSPACE}/${pattern}
    get_bucket_uri "${type}"
    gsutil -m -q cp -r ${bucketUri} ${WORKSPACE}/${pattern}
}

with_mage() {
    local install_packages=(
            "github.com/magefile/mage"
            "github.com/elastic/go-licenser"
            "golang.org/x/tools/cmd/goimports"
            "github.com/jstemmer/go-junit-report"
            "gotest.tools/gotestsum"
    )
    create_workspace
    for pkg in "${install_packages[@]}"; do
    go install "${pkg}@latest"
    done
}

cleanup() {
    echo "Deleting temporary files..."
    if [[ -d "${WORKSPACE}/${TMP_FOLDER_TEMPLATE_BASE}.*" ]]; then
        rm -rf ${WORKSPACE}/${TMP_FOLDER_TEMPLATE_BASE}.*
    fi
    echo "Done."
}