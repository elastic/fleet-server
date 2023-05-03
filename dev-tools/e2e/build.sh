#!/bin/bash

# This script builds an image from the elastic-agent image
# with a locally built fleet-server binary injected. Additional
# flags (e.g. -t <name>) will be passed to `docker build`.

set -eu

REPO_ROOT=$(cd $(dirname $(readlink -f "$0"))/../.. && pwd)

source ${REPO_ROOT}/dev-tools/integration/.env

USER_NAME=${USER}
CI_ELASTIC_AGENT_DOCKER_IMAGE=docker.elastic.co/observability-ci/elastic-agent

BASE_IMAGE="${BASE_IMAGE:-docker.elastic.co/cloud-release/elastic-agent-cloud:$ELASTICSEARCH_VERSION}"
GOARCH="${GOARCH:-$(go env GOARCH)}"

export DOCKER_BUILDKIT=1
docker pull --platform linux/$GOARCH $BASE_IMAGE

STACK_VERSION=$(docker inspect -f '{{index .Config.Labels "org.label-schema.version"}}' $BASE_IMAGE)
VCS_REF=$(docker inspect -f '{{index .Config.Labels "org.label-schema.vcs-ref"}}' $BASE_IMAGE)

CUSTOM_IMAGE_TAG=${STACK_VERSION}-e2e-${USER_NAME}-$(date +%s)

docker build \
	-f $REPO_ROOT/dev-tools/e2e/Dockerfile \
	--build-arg ELASTIC_AGENT_IMAGE=$BASE_IMAGE \
	--build-arg STACK_VERSION=$STACK_VERSION \
	--build-arg VCS_REF_SHORT=${VCS_REF:0:6} \
	--platform linux/$GOARCH \
	-t ${CI_ELASTIC_AGENT_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG} \
	$* $REPO_ROOT/build

echo "${CI_ELASTIC_AGENT_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG}" > ${REPO_ROOT}/build/e2e-image
