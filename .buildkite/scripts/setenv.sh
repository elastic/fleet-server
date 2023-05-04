#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)/bin"

add_bin_path(){
    mkdir -p ${WORKSPACE}
    export PATH="${WORKSPACE}:${PATH}"
}

with_go() {
    mkdir -p ${WORKSPACE}
    retry 5 curl -sL -o ${WORKSPACE}/gvm "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-linux-amd64"
    chmod +x ${WORKSPACE}/gvm
    eval "$(gvm $(cat .go-version))"
    go version
    which go
    echo "Installing dependencies..."
    go get github.com/jstemmer/go-junit-report
    export PATH="$(go env GOPATH):$(go env GOPATH)/bin:${PATH}"
    echo -e "\nPATH="${PATH}"" >> dev-tools/integration/.env
}

with_docker_compose() {
    mkdir -p ${WORKSPACE}
    retry 5 curl -SL -o ${WORKSPACE}/docker-compose "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64"
    chmod +x ${WORKSPACE}/docker-compose
    docker-compose version
    export PATH="${WORKSPACE}:${PATH}"
    echo -e "\nPATH="${PATH}"" >> dev-tools/integration/.env
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

if [ $# -lt 1 ]; then
  echo "Usage: $0 <option>. Examples: "$0 with-go" or "$0 with-docker-compose" or "$0 with-go-docker-compose" "
  exit 1
fi

option=$1

case $option in
  "with-go")
    echo "Setting up Go environment..."
    add_bin_path
    with_go
    ;;
  "with-docker-compose")
    echo "Setting up Docker-compose environment......"
    add_bin_path
    with_docker_compose
    ;;
  "with-go-docker-compose")
    echo "Setting up Docker-compose and GO environments......"
    add_bin_path
    with_go
    with_docker_compose
    ;;
  *)
    echo "unexpected input: $option. Please use with-go or with-docker-compose or with-go-docker-compose options."
    exit 1
    ;;
esac
