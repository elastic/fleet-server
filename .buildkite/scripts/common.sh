#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)/bin"
TMP_FOLDER_TEMPLATE_BASE="tmp.fleet-server"
REPO="fleet-server"

add_bin_path(){
    echo "Adding PATH to the environment variables..."
    mkdir -p ${WORKSPACE}
    export PATH="${PATH}:${WORKSPACE}"
}

with_go() {
    echo "Setting up the Go environment..."
    mkdir -p ${WORKSPACE}
    retry 5 curl -sL -o ${WORKSPACE}/gvm "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-linux-amd64"
    chmod +x ${WORKSPACE}/gvm
    eval "$(gvm $(cat .go-version))"
    go version
    which go
    export PATH="${PATH}:$(go env GOPATH):$(go env GOPATH)/bin"
}

with_docker_compose() {
    echo "Setting up the Docker-compose environment..."
    mkdir -p ${WORKSPACE}
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
    mkdir -p ${WORKSPACE}
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

cleanup() {
    echo "Deleting temporal files..."
    cd ${WORKSPACE}
    rm -rf ${TMP_FOLDER_TEMPLATE_BASE}.*
    echo "Done."
}