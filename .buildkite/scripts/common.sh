#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)/bin"

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
    export PATH="${PATH}:${WORKSPACE}"
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
    echo "Pushing the docker image "$DOCKER_IMAGE":"$DOCKER_IMAGE_PUBLISH_TAG" to the "${DOCKER_REGISTRY}" registry..."
    docker tag "testtag" "${DOCKER_IMAGE}":"${DOCKER_IMAGE_PUBLISH_TAG}"
    docker push "${DOCKER_IMAGE}":"${DOCKER_IMAGE_PUBLISH_TAG}"
}

docker_logout() {
    echo "Logging out from Docker..."
    docker logout ${DOCKER_REGISTRY}
}
