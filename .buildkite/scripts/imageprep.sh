#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

MESSAGE="Usage: $0 <option>. Examples: '$0 build-image' or '$0 push-image' or '$0 retag-and-push-image' "

if [ $# -lt 1 ]; then
  echo "${MESSAGE}"
  exit 1
fi

option=$1

case $option in
  "build-image")
    echo "Building the docker image..."
    docker_login
    if ! docker pull -q ${DOCKER_IMAGE}:${DOCKER_IMAGE_SHA_TAG} 2> /dev/null; then
        DOCKER_IMAGE="${DOCKER_IMAGE}"
        DOCKER_IMAGE_TAG="${DOCKER_IMAGE_SHA_TAG}"
        make build-docker
    fi
    ;;
  "push-image")
        DOCKER_IMAGE_TAG="${DOCKER_IMAGE_SHA_TAG}"
        publish_docker_image
    ;;
  "retag-and-push-image")
    echo "Retagging images..."
    if ${BUILDKITE_TAG}; then
        docker tag "${DOCKER_IMAGE}":"${DOCKER_IMAGE_SHA_TAG}" "${DOCKER_IMAGE}":"${DOCKER_IMAGE_GIT_TAG}"
        DOCKER_IMAGE_TAG="${DOCKER_IMAGE_GIT_TAG}"
        publish_docker_image
    else
        docker tag "${DOCKER_IMAGE}":"${DOCKER_IMAGE_SHA_TAG}" "${DOCKER_IMAGE}":"${DOCKER_IMAGE_LATEST_TAG}"
        DOCKER_IMAGE_TAG="${DOCKER_IMAGE_LATEST_TAG}"
        publish_docker_image
    fi
    ;;
  *)
    echo -e "Unexpected input: $option.\n"${MESSAGE}""
    exit 1
    ;;
esac
