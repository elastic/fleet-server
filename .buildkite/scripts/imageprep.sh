#!/bin/bash

set -euo pipefail

publish_docker_image() {
    echo "Pushing the docker image "$DOCKER_IMAGE:$DOCKER_IMAGE_TAG" to the ${DOCKER_REGISTRY} registry..."
#    docker login "$DOCKER_REGISTRY"                    # we don't have docker-registry credentials
#    docker push "$DOCKER_IMAGE:$DOCKER_IMAGE_TAG"      # we don't have docker-registry credentials
#    docker logout "$DOCKER_REGISTRY"                   # we don't have docker-registry credentials
}


if [ $# -lt 1 ]; then
  echo "Usage: $0 <option>. Examples: "$0 build-image" or "$0 push-image" or "$0 retag-and-push-image" "
  exit 1
fi

option=$1

case $option in
  "build-image")
    echo "Building the docker image..."
#    if ! docker pull -q ${DOCKER_IMAGE}:${DOCKER_IMAGE_SHA_TAG} 2> /dev/null; then     # we don't have docker-registry credentials
        DOCKER_IMAGE=${DOCKER_IMAGE}
        DOCKER_IMAGE_TAG=${DOCKER_IMAGE_SHA_TAG}
        make build-docker
#    fi                                                                                 # we don't have docker-registry credentials
    ;;
  "push-image")
         publish_docker_image
    ;;
  "retag-and-push-image")
    echo "Retagging images..."
    if ${BUILDKITE_TAG}; then
        docker tag ${DOCKER_IMAGE}:${DOCKER_IMAGE_SHA_TAG} ${DOCKER_IMAGE}:${DOCKER_IMAGE_GIT_TAG}
        DOCKER_IMAGE_TAG=${DOCKER_IMAGE_GIT_TAG}
        publish_docker_image
    else
        docker tag ${DOCKER_IMAGE}:${DOCKER_IMAGE_SHA_TAG} ${DOCKER_IMAGE}:${DOCKER_IMAGE_LATEST_TAG}
        DOCKER_IMAGE_TAG=${DOCKER_IMAGE_LATEST_TAG}
        publish_docker_image
    fi
    ;;
  *)
    echo "unexpected input: $option. Please use build-image or push-image or retag-image options."
    exit 1
    ;;
esac
