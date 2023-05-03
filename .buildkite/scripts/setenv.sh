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
    echo "export PATH=\$(go env GOPATH):${PATH}" >> ~/.bashrc
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

add_bin_path

with_go
