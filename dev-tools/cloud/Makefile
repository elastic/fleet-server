MAKEFILE_PATH:=$(abspath $(lastword ${MAKEFILE_LIST}))
MAKEFILE_DIR:=$(dir ${MAKEFILE_PATH})
REPO_ROOT:=$(abspath ${MAKEFILE_DIR}/../../)
SNAPSHOT_SUFFIX:=-SNAPSHOT
ifeq (${SNAPSHOT}, false)
SNAPSHOT_SUFFIX:=""
endif
ifeq (${SNAPSHOT}, 0)
SNAPSHOT_SUFFIX:=""
endif
VERSION:=$(shell grep "const DefaultVersion" ${REPO_ROOT}/version/version.go | cut -d\" -f2)${SNAPSHOT_SUFFIX}

export DOCKER_BUILDKIT=1

USER_NAME?=${USER}
CI_ELASTIC_AGENT_DOCKER_IMAGE:=docker.elastic.co/observability-ci/elastic-agent
CUSTOM_IMAGE_TAG:=${VERSION}-${USER_NAME}-$(shell date +%s)

TERRAFORM_PATH:=${REPO_ROOT}/dev-tools/cloud/terraform

##################################################
# Cloud testing targets
##################################################
.PHONY: build-and-push-cloud-image
build-and-push-cloud-image:
	echo $(CUSTOM_IMAGE_TAG)
	GOARCH=amd64 CI_ELASTIC_AGENT_DOCKER_IMAGE=${CI_ELASTIC_AGENT_DOCKER_IMAGE} CUSTOM_IMAGE_TAG=${CUSTOM_IMAGE_TAG} ${REPO_ROOT}/dev-tools/cloud/docker/build.sh

.PHONY: deploy-cloud
deploy-cloud: build-and-push-cloud-image  ## Create a new cloud deployment
	@cd ${TERRAFORM_PATH}; terraform init; TF_VAR_elastic_agent_docker_image="${CI_ELASTIC_AGENT_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG}" terraform apply -auto-approve

.PHONY: clean-cloud
clean-cloud: ## Clean cloud deployment
	@cd ${TERRAFORM_PATH}; terraform destroy -auto-approve

.PHONY: test
test: build-and-push-cloud-image ## Clean cloud deployment
	echo $(CUSTOM_IMAGE_TAG)
	GOARCH=amd64 CUSTOM_IMAGE_TAG=${CUSTOM_IMAGE_TAG} ${REPO_ROOT}/dev-tools/cloud/docker/build.sh
	@cd ${TERRAFORM_PATH}; echo 'elastic_agent_docker_image="${CI_ELASTIC_AGENT_DOCKER_IMAGE}:${CUSTOM_IMAGE_TAG}"' >> docker_image.auto.tfvars

