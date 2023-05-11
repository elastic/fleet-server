#!/bin/bash

set -euo pipefail

source .buildkite/scripts/setenv.sh

DOCKER_REGISTRY="docker.elastic.co"
DOCKER_REGISTRY_SECRET_PATH="kv/ci-shared/platform-ingest/docker_registry_prod"

publish_docker_image() {
    echo "Pushing the docker image "$DOCKER_IMAGE":"$DOCKER_IMAGE_TAG" to the "${DOCKER_REGISTRY}" registry..."
    docker_login
    docker push "${DOCKER_IMAGE}":"${DOCKER_IMAGE_TAG}"
    docker logout "$DOCKER_REGISTRY"
}

docker_login() {
    DOCKER_USER=$(retry 5 vault kv get -field user "${DOCKER_REGISTRY_SECRET_PATH}")
    DOCKER_PASSWORD=$(retry 5 vault kv get -field password "${DOCKER_REGISTRY_SECRET_PATH}")
    docker login -u "${DOCKER_USER}" -p "${DOCKER_PASSWORD}" "${DOCKER_REGISTRY}" 2>/dev/null
}

if [ $# -lt 1 ]; then
  echo "Usage: $0 <option>. Examples: "$0 build-image" or "$0 push-image" or "$0 retag-and-push-image" "
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
    docker logout "$DOCKER_REGISTRY"
    ;;
  "push-image")
        DOCKER_IMAGE_TAG="${DOCKER_IMAGE_SHA_TAG}"
        publish_docker_image
    ;;
  "retag-and-push-image")
    echo "Retagging images..."
    if ${BUILDKITE_TAG}; then
        DOCKER_IMAGE_GIT_TAG=$(echo "${DOCKER_IMAGE_GIT_TAG}" | sed 's/:/-/g')                      # temporary solution for tests -replace one extra symbol ":" to "-" in the tag because of the push issue
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
    echo "unexpected input: $option. Please use build-image or push-image or retag-image options."
    exit 1
    ;;
esac
