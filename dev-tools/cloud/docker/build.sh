#!/bin/bash

# This script builds an image from the elastic-agent image
# with a locally built fleet-server binary injected. Additional
# flags (e.g. -t <name>) will be passed to `docker build`.

set -eu

REPO_ROOT=$(cd $(dirname $(readlink -f "$0"))/../../.. && pwd)

USER_NAME=${USER}
CI_ELASTIC_AGENT_DOCKER_IMAGE=${CI_ELASTIC_AGENT_DOCKER_IMAGE:-"docker.elastic.co/observability-ci/elastic-agent"}

source $REPO_ROOT/dev-tools/integration/.env

DEFAULT_IMAGE_TAG=$ELASTICSEARCH_VERSION
BASE_IMAGE="${BASE_IMAGE:-docker.elastic.co/cloud-release/elastic-agent-cloud:$DEFAULT_IMAGE_TAG}"
GOARCH="${GOARCH:-$(go env GOARCH)}"

export DOCKER_BUILDKIT=1
docker pull --platform linux/$GOARCH $BASE_IMAGE

STACK_VERSION=$(docker inspect -f '{{index .Config.Labels "org.label-schema.version"}}' $BASE_IMAGE)
VCS_REF=$(docker inspect -f '{{index .Config.Labels "org.label-schema.vcs-ref"}}' $BASE_IMAGE)

CUSTOM_IMAGE_TAG=${CUSTOM_IMAGE_TAG:-"${STACK_VERSION}-${USER_NAME}-$(date +%s)"}

SNAPSHOT=true make -C $REPO_ROOT release-linux/${GOARCH}
FLEET_VERSION=$(SNAPSHOT=true make -C $REPO_ROOT get-version)
echo "Fleet version: ${FLEET_VERSION}"

docker build \
	-f $REPO_ROOT/dev-tools/cloud/docker/Dockerfile \
	--build-arg ELASTIC_AGENT_IMAGE=$BASE_IMAGE \
	--build-arg STACK_VERSION=${FLEET_VERSION} \
	--build-arg VCS_REF_SHORT=${VCS_REF:0:6} \
	--platform linux/$GOARCH \
	-t ${CI_ELASTIC_AGENT_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG} \
	$* $REPO_ROOT/build


docker push ${CI_ELASTIC_AGENT_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG}

echo "Image available at:"
echo "${CI_ELASTIC_AGENT_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG}"
