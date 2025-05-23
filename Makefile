# Makefile for fleet-server
# Many of the targets can change behaviour based on the following flags:
# - SNAPSHOT - true/false (default false); Make a SNAPSHOT build; fleet-server will allow agents on the next minor version to connect
# - DEV - true/false (default false); Make a dev build, compiler inlining and optimizations are disabled and the symbols table is kept
# - FIPS - true/false (default false); Make a FIPS build.
#
# Additionally the PLATFORMS env var can be used to deterimine outputs for specific targets, such as release.

SHELL=/usr/bin/env bash
GO_VERSION=$(shell cat '.go-version')
# Use workflow file as source of truth for golangci-lint version
GOLANGCI_LINT_VERSION=$(shell grep 'version:' .github/workflows/golangci-lint.yml | cut -d : -f 2 | tr -d ' ')
DEFAULT_VERSION=$(shell awk '/const DefaultVersion/{print $$NF}' version/version.go | tr -d '"')

# Set FIPS=true to force FIPS compliance when building
FIPS?=false

ifeq "${FIPS}" "true"
PLATFORMS ?= linux/amd64 linux/arm64
else
PLATFORMS ?= darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64
endif

TARGET_ARCH_amd64=x86_64
TARGET_ARCH_arm64=arm64
BUILDMODE_linux_amd64=-buildmode=pie
BUILDMODE_linux_arm64=-buildmode=pie
BUILDMODE_windows_amd64=-buildmode=pie
BUILDMODE_darwin_amd64=-buildmode=pie
BUILDMODE_darwin_arm64=-buildmode=pie

CROSSBUILD_SUFFIX=main-debian11
CROSSBUILD_ARM_SUFFIX=base-arm-debian9
STANDALONE_DOCKERFILE=Dockerfile
BUILDER_IMAGE=fleet-server-builder:${GO_VERSION}

#Benchmark related targets
BENCH_BASE ?= benchmark-$(COMMIT).out
BENCH_NEXT ?=
BENCHMARK_ARGS := -count=10 -benchtime=3s -benchmem
BENCHMARK_PACKAGE ?= ./...
BENCHMARK_FILTER ?= Bench

GO_TEST_FLAG =
ifdef TEST_COVERAGE
GO_TEST_FLAG = -covermode=atomic -coverprofile=build/TEST-go-fleet-server-coverage.cov
endif

#Cloud testing env target
CLOUD_TESTING_BASE=./dev-tools/cloud

ifdef VERSION_QUALIFIER
DEFAULT_VERSION:=${DEFAULT_VERSION}-${VERSION_QUALIFIER}
endif

# gobuildtags is an intermediate variable that is used to properly assemble GOBUILDTAGS, a comma seperated list of tags to use with go build
gobuildtags=grpcnotrace
ifeq ($(SNAPSHOT),true)
VERSION=${DEFAULT_VERSION}-SNAPSHOT
gobuildtags += snapshot
else
VERSION=${DEFAULT_VERSION}
endif

DOCKER_IMAGE?=docker.elastic.co/fleet-server/fleet-server
DOCKER_PLATFORMS ?= linux/amd64 linux/arm64
# defing the docker image tag used for stand-alone fleet-server images
# only want to define the tag if none is specified, this allows an invocation like
#    FIPS=true make test-e2e
# to use a tag like X.Y.Z-fips and not X.Y.Z-fips-fips as the test-e2e target calls into make
ifndef DOCKER_IMAGE_TAG
DOCKER_IMAGE_TAG?=${VERSION}
ifeq "${DEV}" "true"
DOCKER_IMAGE_TAG:=${DOCKER_IMAGE_TAG}-dev
endif
endif

PLATFORM_TARGETS=$(addprefix release-, $(PLATFORMS))
COVER_TARGETS=$(addprefix cover-, $(PLATFORMS))
COMMIT=$(shell git rev-parse --short HEAD)
NOW=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
CMD_COLOR_ON=\033[32m\xE2\x9c\x93
CMD_COLOR_OFF=\033[0m

LDFLAGS=-X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=$(NOW)
ifeq ($(strip $(DEV)),)
GCFLAGS ?=
LDFLAGS:=-s -w ${LDFLAGS}
else
GCFLAGS ?= all=-N -l
endif

# Directory to dump build tools into
GOBIN=$(shell go env GOPATH)/bin/

OS_NAME:=$(shell uname -s)

# NOTE: We are assuming that the only GOEXPIREMENT flag will be associated with FIPS
GOFIPSEXPERIMENT?=
FIPSSUFFIX=
ifeq "${FIPS}" "true"
BUILDER_IMAGE=fleet-server-fips-builder:${GO_VERSION}
DOCKER_IMAGE:=docker.elastic.co/fleet-server/fleet-server-fips
STANDALONE_DOCKERFILE=Dockerfile.fips
gobuildtags += requirefips ms_tls13kdf
GOFIPSEXPERIMENT=GOEXPERIMENT=systemcrypto CGO_ENABLED=1
FIPSSUFFIX=-fips
endif

# Assemble GOBUILDTAGS with some Makefile trickery as we need to avoid sending multiple -tags flags
# the character of a comma needs a variable so it can be used as a value in a subst call
comma=,
# transform the space-seperated values in gobuildtags to a comma seperated string
GOBUILDTAGS=$(subst $() $(),$(comma),$(gobuildtags))

.EXPORT_ALL_VARIABLES:
	FIPS=${FIPS}

.PHONY: help
help: ## - Show help message
	@printf "${CMD_COLOR_ON} usage: make [target]\n\n${CMD_COLOR_OFF}"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | sed -e "s/^Makefile://" | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: multipass
multipass: ## - Launch a multipass instance for development
ifeq ($(shell uname -p),arm)
	$(eval ARCH := arm64)
else
	$(eval ARCH := amd64)
endif
ifeq "${FIPS}" "true"
	$(eval DOWNLOAD_URL := https://aka.ms/golang/release/latest/go${GO_VERSION}-1.linux-${ARCH}.tar.gz)
else
	$(eval DOWNLOAD_URL := https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz)
endif
	@cat dev-tools/multipass-cloud-init.yml.envsubst | DOWNLOAD_URL=${DOWNLOAD_URL} ARCH=${ARCH} envsubst > dev-tools/multipass-cloud-init.yml
	@multipass launch --cloud-init=dev-tools/multipass-cloud-init.yml --mount ..:~/git --name fleet-server-dev --memory 8G --cpus 2 --disk 50G noble
	@rm dev-tools/multipass-cloud-init.yml

.PHONY: list-platforms
list-platforms: ## - Show the possible PLATFORMS
	@echo  "${PLATFORMS}"

.PHONY: local
local: ## - Build local binary for local environment (bin/fleet-server)
	@printf "${CMD_COLOR_ON} Build binaries using local go installation\n${CMD_COLOR_OFF}"
	${GOFIPSEXPERIMENT} go build -tags=${GOBUILDTAGS} -gcflags="${GCFLAGS}" -ldflags="${LDFLAGS}" -o ./bin/fleet-server .
	@printf "${CMD_COLOR_ON} Binaries in ./bin/\n${CMD_COLOR_OFF}"

.PHONY: $(COVER_TARGETS)
$(COVER_TARGETS): cover-%: ## - Build a binary with the -cover flag for integration testing
	@mkdir -p build/cover
	$(eval $@_OS := $(firstword $(subst /, ,$(lastword $(subst cover-, ,$@)))))
	$(eval $@_GO_ARCH := $(lastword $(subst /, ,$(lastword $(subst cover-, ,$@)))))
	$(eval $@_ARCH := $(TARGET_ARCH_$($@_GO_ARCH)))
	$(eval $@_BUILDMODE:= $(BUILDMODE_$($@_OS)_$($@_GO_ARCH)))
	GOOS=$($@_OS) GOARCH=$($@_GO_ARCH) ${GOFIPSEXPERIMENT} go build -tags=${GOBUILDTAGS} -cover -coverpkg=./... -gcflags="${GCFLAGS}" -ldflags="${LDFLAGS}" $($@_BUILDMODE) -o build/cover/fleet-server$(FIPSSUFFIX)-$(VERSION)-$($@_OS)-$($@_ARCH)/fleet-server$(if $(filter windows,$($@_OS)),.exe,) .

.PHONY: clean
clean: ## - Clean up build artifacts
	@printf "${CMD_COLOR_ON} Clean up build artifacts\n${CMD_COLOR_OFF}"
	rm -rf .service_token* .kibana_service_token ./bin/ ./build/

.PHONY: generate
generate: ## - Generate schema models
	@printf "${CMD_COLOR_ON} Running go generate\n${CMD_COLOR_OFF}"
	env PATH="${GOBIN}:${PATH}" go generate ./...
	@$(MAKE) check-headers

.PHONY: check-ci
check-ci: ## - Run all checks of the ci without linting, the linter is run through github action to have comments in the pull-request.
	@$(MAKE) generate
	@$(MAKE) check-headers
	@$(MAKE) notice
	@$(MAKE) check-no-changes

.PHONY: check
check: ## - Run all checks
	@$(MAKE) check-ci
	@$(MAKE) check-go

.PHONY: check-headers
check-headers:  ## - Check copyright headers
	@go tool -modfile ./dev-tools/go.mod github.com/elastic/go-licenser -license Elastic

.PHONY: check-go
check-go: ## - Run golangci-lint
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/d58dbde584c801091e74a00940e11ff18c6c68bd/install.sh | sh -s $(GOLANGCI_LINT_VERSION)
	@./bin/golangci-lint run -v

.PHONY: notice
notice: ## - Generates the NOTICE.txt file.
	@echo "Generating NOTICE.txt"
	@go mod tidy
	@go mod download all
	go list -m -json all | go tool -modfile ./dev-tools/go.mod go.elastic.co/go-licence-detector \
		-includeIndirect \
		-rules dev-tools/notice/rules.json \
		-overrides dev-tools/notice/overrides.json \
		-noticeTemplate dev-tools/notice/NOTICE.txt.tmpl \
		-noticeOut NOTICE.txt \
		-depsOut ""
	@# Ensure the go.mod file is left unchanged after go mod download all runs.
	@# go mod download will modify go.sum in a way that conflicts with go mod tidy.
	@# https://github.com/golang/go/issues/43994#issuecomment-770053099
	@go mod tidy

.PHONY: check-no-changes
check-no-changes:
	@git diff | cat
	@git update-index --refresh
	@git diff-index --exit-code HEAD --

.PHONY: test
test: prepare-test-context  ## - Run all tests
	@./dev-tools/run_with_go_ver $(MAKE) test-unit
	@./dev-tools/run_with_go_ver $(MAKE) test-int
	@$(MAKE) junit-report

.PHONY: test-release
test-release:  ## - Check that all release binaries are created
	./.buildkite/scripts/test-release.sh $(DEFAULT_VERSION)

.PHONY: test-unit
test-unit: prepare-test-context  ## - Run unit tests only
	set -o pipefail; go test ${GO_TEST_FLAG} -tags=$(GOBUILDTAGS) -v -race -coverprofile=build/coverage-${OS_NAME}.out ./... | tee build/test-unit-${OS_NAME}.out

.PHONY: test-fips-provider-unit
test-fips-provider-unit: prepare-test-context  ## - Run unit tests with GOEXPERIMENT=systemcrypto to check that system FIPS provider works
	set -o pipefail; GOEXPERIMENT=systemcrypto CGO_ENABLED=1 go test ${GO_TEST_FLAG} -tags=$(GOBUILDTAGS) -v -race -coverprofile=build/coverage-${OS_NAME}.out ./... | tee build/test-unit-${OS_NAME}.out

.PHONY: benchmark
benchmark: prepare-test-context ## - Run benchmark tests only
	set -o pipefail; go test -bench=$(BENCHMARK_FILTER) -tags=$(GOBUILDTAGS) -run=$(BENCHMARK_FILTER) $(BENCHMARK_ARGS) $(BENCHMARK_PACKAGE) | tee "build/$(BENCH_BASE)"

.PHONY: benchstat
benchstat: ## - Run the benchstat comparing base against next, BENCH_BASE and BENCH_NEXT are required for comparison
	$(eval BENCHSTAT_ARGS := "build/$(BENCH_BASE)")
ifneq ($(BENCH_NEXT),)
	$(eval BENCHSTAT_ARGS += "build/$(BENCH_NEXT)")
endif
	@go tool -modfile ./dev-tools/go.mod golang.org/x/perf/cmd/benchstat $(BENCHSTAT_ARGS)

.PHONY: prepare-test-context
prepare-test-context: ## - Prepare the test context folders
	@mkdir -p build

.PHONY: junit-report
junit-report: ## - Run the junit-report generation for all the out files generated
	$(foreach file, $(wildcard build/*.out), go tool -modfile ./dev-tools/go.mod github.com/jstemmer/go-junit-report > "${file}.xml" < ${file};)

##################################################
# Release building targets
##################################################

build/distributions:
	@mkdir -p build/distributions

.PHONY: $(PLATFORM_TARGETS)
$(PLATFORM_TARGETS): release-%:
	$(eval $@_OS := $(firstword $(subst /, ,$(lastword $(subst release-, ,$@)))))
	$(eval $@_GO_ARCH := $(lastword $(subst /, ,$(lastword $(subst release-, ,$@)))))
	$(eval $@_ARCH := $(TARGET_ARCH_$($@_GO_ARCH)))
	$(eval $@_BUILDMODE:= $(BUILDMODE_$($@_OS)_$($@_GO_ARCH)))
	GOOS=$($@_OS) GOARCH=$($@_GO_ARCH) ${GOFIPSEXPERIMENT} go build -tags=${GOBUILDTAGS} -gcflags="${GCFLAGS}" -ldflags="${LDFLAGS}" $($@_BUILDMODE) -o build/binaries/fleet-server$(FIPSSUFFIX)-$(VERSION)-$($@_OS)-$($@_ARCH)/fleet-server .
	@$(MAKE) OS=$($@_OS) ARCH=$($@_ARCH) package-target

.PHONY: build-docker
build-docker:
	DOCKER_BUILDKIT=1 docker build \
		--build-arg GO_VERSION=$(GO_VERSION) \
		--build-arg=GCFLAGS="${GCFLAGS}" \
		--build-arg=LDFLAGS="${LDFLAGS}" \
		--build-arg=DEV="$(DEV)" \
		--build-arg=SNAPSHOT="$(SNAPSHOT)" \
		--build-arg=VERSION="$(VERSION)" \
		-f $(STANDALONE_DOCKERFILE) \
		-t $(DOCKER_IMAGE):$(DOCKER_IMAGE_TAG) .

.PHONY: build-and-push-docker
build-and-push-docker:
	docker buildx create --use
	docker buildx build --push \
		--platform $(shell echo ${DOCKER_PLATFORMS} | sed 's/ /,/g') \
		--build-arg GO_VERSION=$(GO_VERSION) \
		--build-arg=GCFLAGS="${GCFLAGS}" \
		--build-arg=LDFLAGS="${LDFLAGS}" \
		--build-arg=DEV="$(DEV)" \
		--build-arg=SNAPSHOT="$(SNAPSHOT)" \
		--build-arg=VERSION="$(VERSION)" \
		-t $(DOCKER_IMAGE):$(DOCKER_IMAGE_TAG) .

.PHONY: release-docker
release-docker:
	docker push \
		$(DOCKER_IMAGE):$(DOCKER_IMAGE_TAG)

.PHONY: package-target
package-target: build/distributions
ifeq ($(OS),windows)
	@mv build/binaries/fleet-server-$(VERSION)-$(OS)-$(ARCH)/fleet-server build/binaries/fleet-server-$(VERSION)-$(OS)-$(ARCH)/fleet-server.exe
	@cd build/binaries && zip -q -r ../distributions/fleet-server-$(VERSION)-$(OS)-$(ARCH).zip fleet-server-$(VERSION)-$(OS)-$(ARCH)
	@cd build/distributions && sha512sum fleet-server-$(VERSION)-$(OS)-$(ARCH).zip > fleet-server-$(VERSION)-$(OS)-$(ARCH).zip.sha512
else ifeq ($(OS)-$(ARCH),darwin-arm64)
	@mv build/binaries/fleet-server-$(VERSION)-$(OS)-$(ARCH) build/binaries/fleet-server-$(VERSION)-$(OS)-aarch64
	@tar -C build/binaries -zcf build/distributions/fleet-server-$(VERSION)-$(OS)-aarch64.tar.gz fleet-server-$(VERSION)-$(OS)-aarch64
	@cd build/distributions && sha512sum fleet-server-$(VERSION)-$(OS)-aarch64.tar.gz > fleet-server-$(VERSION)-$(OS)-aarch64.tar.gz.sha512
else
	@tar -C build/binaries -zcf build/distributions/fleet-server$(FIPSSUFFIX)-$(VERSION)-$(OS)-$(ARCH).tar.gz fleet-server$(FIPSSUFFIX)-$(VERSION)-$(OS)-$(ARCH)
	@cd build/distributions && sha512sum fleet-server$(FIPSSUFFIX)-$(VERSION)-$(OS)-$(ARCH).tar.gz > fleet-server$(FIPSSUFFIX)-$(VERSION)-$(OS)-$(ARCH).tar.gz.sha512
endif

build-releaser: ## - Build a Docker image to run make package including all build tools
ifeq ($(shell uname -p),arm)
	$(eval SUFFIX := ${CROSSBUILD_ARM_SUFFIX})
else
	$(eval SUFFIX := ${CROSSBUILD_SUFFIX})
endif
ifeq "${FIPS}" "true"
	docker build -t $(BUILDER_IMAGE) -f Dockerfile.fips --target base --build-arg GO_VERSION=$(GO_VERSION) .
else
	docker build -t $(BUILDER_IMAGE) -f Dockerfile.build --build-arg GO_VERSION=$(GO_VERSION) --build-arg SUFFIX=${SUFFIX} .
endif

.PHONY: docker-release
docker-release: build-releaser ## - Builds a release for all platforms in a dockerised environment
	docker run --rm -u $(shell id -u):$(shell id -g) --env=GOCACHE=/go/cache --volume $(PWD):/go/src/github.com/elastic/fleet-server $(BUILDER_IMAGE) release

.PHONY: docker-cover-e2e-binaries
docker-cover-e2e-binaries: build-releaser
ifeq "${FIPS}" "true"
	## non-linux is currently unsupported for FIPS
	docker run --rm -u $(shell id -u):$(shell id -g) --env=GOCACHE=/go/cache --volume $(PWD):/go/src/github.com/elastic/fleet-server -e SNAPSHOT=true -e DEV=$(DEV) -e FIPS=$(FIPS) $(BUILDER_IMAGE) cover-linux/$(shell go env GOARCH)
else
	## Build for local architecture and for linux/$ARCH for docker images.
	docker run --rm -u $(shell id -u):$(shell id -g) --env=GOCACHE=/go/cache --volume $(PWD):/go/src/github.com/elastic/fleet-server -e SNAPSHOT=true -e DEV=$(DEV) -e FIPS=$(FIPS) $(BUILDER_IMAGE) cover-linux/$(shell go env GOARCH) cover-$(shell go env GOOS)/$(shell go env GOARCH)
endif

.PHONY: release
release: $(PLATFORM_TARGETS) ## - Builds a release. Specify exact platform with PLATFORMS env.

release-manager-dependencies: ## - Prepares the dependencies file.
	@mkdir -p build/distributions/reports
	./dev-tools/run_with_go_ver dev-tools/dependencies-report --csv build/distributions/reports/dependencies-$(VERSION).csv
	@cd build/distributions/reports && shasum -a 512 dependencies-$(VERSION).csv > dependencies-$(VERSION).csv.sha512

.PHONY: release-manager-dependencies-snapshot
release-manager-dependencies-snapshot: ## - Prepares the dependencies file for a snapshot.
	@$(MAKE) SNAPSHOT=true release-manager-dependencies

.PHONY: release-manager-dependencies-release
release-manager-dependencies-release: ## - Prepares the dependencies file for a release.
	@$(MAKE) release-manager-dependencies

.PHONY: release-manager-snapshot
release-manager-snapshot: ## - Builds a snapshot release. The Go version defined in .go-version will be installed and used for the build.
	@$(MAKE) SNAPSHOT=true release-manager-release

.PHONY: release-manager-release
release-manager-release: ## - Builds a snapshot release. The Go version defined in .go-version will be installed and used for the build.
	./dev-tools/run_with_go_ver $(MAKE) release

## get-version : Get the Fleet server version
.PHONY: get-version
get-version:
	@echo $(VERSION)

##################################################
# Integration testing targets
##################################################

# Load environment (ES version and creds)
include ./dev-tools/integration/.env
export $(shell sed 's/=.*//' ./dev-tools/integration/.env)

# Start integration docker setup with wait for when the ES is ready
.PHONY: int-docker-start
int-docker-start: ## - Start docker envronment for integration tests and wait until it's ready
	docker compose -f ./dev-tools/integration/docker-compose.yml --env-file ./dev-tools/integration/.env up  -d --wait --remove-orphans elasticsearch elasticsearch-remote

# Stop integration docker setup
.PHONY: int-docker-stop
int-docker-stop: ## - Stop docker environment for integration tests
	@docker compose -f ./dev-tools/integration/docker-compose.yml --env-file ./dev-tools/integration/.env down
	@rm -f .service_token*

# Run integration tests with starting/stopping docker
.PHONY: test-int
test-int: prepare-test-context  ## - Run integration tests with full setup (slow!)
	@$(MAKE) int-docker-start
	@set -o pipefail; $(MAKE) test-int-set | tee build/test-int.out
	@$(MAKE) int-docker-stop

# Run integration tests without starting/stopping docker
# Useful for development where you:
# 1. Start integration environment
# 2. Develop/test/repeat
# 3  Stop integration environment when done
.PHONY: test-int-set
test-int-set: ## - Run integration tests without setup
	# Initialize indices one before running all the tests
	ELASTICSEARCH_SERVICE_TOKEN=$(shell ./dev-tools/integration/get-elasticsearch-servicetoken.sh ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}@${TEST_ELASTICSEARCH_HOSTS} "fleet-server") \
	REMOTE_ELASTICSEARCH_SERVICE_TOKEN=$(shell ./dev-tools/integration/get-elasticsearch-servicetoken.sh https://${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}@${TEST_REMOTE_ELASTICSEARCH_HOST} "fleet-server-remote") \
	REMOTE_ELASTICSEARCH_CA_CRT_BASE64="$(shell COMPOSE_PROJECT_NAME=integration docker compose  -f ./dev-tools/e2e/docker-compose.yml --env-file ./dev-tools/integration/.env exec elasticsearch-remote /bin/bash -c "cat /usr/share/elasticsearch/config/certs/ca/ca.crt" | base64)" \
	ELASTICSEARCH_HOSTS=${TEST_ELASTICSEARCH_HOSTS} ELASTICSEARCH_USERNAME=${ELASTICSEARCH_USERNAME} ELASTICSEARCH_PASSWORD=${ELASTICSEARCH_PASSWORD} \
	go test -v -tags=integration -count=1 -race -p 1 ./...

##################################################
# e2e testing targets
##################################################

# based off build-and-push-cloud-image
.PHONY: build-e2e-agent-image
build-e2e-agent-image: docker-cover-e2e-binaries ## - Build a custom elastic-agent image with fleet-server binaries with coverage enabled injected
	@printf "${CMD_COLOR_ON} Creating test e2e agent image\n${CMD_COLOR_OFF}"
	FIPS=${FIPS} FLEET_VERSION=${DEFAULT_VERSION}-SNAPSHOT ./dev-tools/e2e/build.sh # force fleet version to be equal to VERSION-SNAPSHOT

.PHONY: e2e-certs
e2e-certs: ## - Use openssl to create a CA, encrypted private key, and signed fleet-server cert testing purposes
	@printf "${CMD_COLOR_ON} Creating test e2e certs\n${CMD_COLOR_OFF}"
	@./dev-tools/e2e/certs.sh

.PHONY: e2e-docker-start
e2e-docker-start: int-docker-start ## - Start a testing instance of Elasticsearch and Kibana in docker containers
	@KIBANA_TOKEN=$(shell ./dev-tools/e2e/get-kibana-servicetoken.sh ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}@${TEST_ELASTICSEARCH_HOSTS}) \
		APM_KEY=$(shell ./dev-tools/e2e/get-apm-server-api-key.sh ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}@${TEST_ELASTICSEARCH_HOSTS}) \
		docker compose -f ./dev-tools/e2e/docker-compose.yml --env-file ./dev-tools/integration/.env up  -d --remove-orphans kibana --remove-orphans apm-server --wait
	@./dev-tools/e2e/wait-for-apm.sh localhost:8200

.PHONY: e2e-docker-stop
e2e-docker-stop: ## - Tear down testing Elasticsearch and Kibana instances
	@KIBANA_TOKEN="supress-warning" APM_KEY="supress-warning" docker compose -f ./dev-tools/e2e/docker-compose.yml --env-file ./dev-tools/integration/.env down
	rm -f .kibana_service_token .apm_server_api_key
	@$(MAKE) int-docker-stop

.PHONY: test-e2e
test-e2e: docker-cover-e2e-binaries build-e2e-agent-image e2e-certs build-docker ## - Setup and run the blackbox end to end test suite
	@mkdir -p build/e2e-cover
	@$(MAKE) e2e-docker-start
	@set -o pipefail; $(MAKE) test-e2e-set | tee build/test-e2e.out
	@$(MAKE) e2e-docker-stop
	@go tool covdata textfmt -i=build/e2e-cover -o=build/e2e-coverage.out

.PHONY: test-e2e-set
test-e2e-set: ## - Run the blackbox end to end tests without setup.
	cd testing; \
	ELASTICSEARCH_SERVICE_TOKEN=$(shell ./dev-tools/integration/get-elasticsearch-servicetoken.sh ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}@${TEST_ELASTICSEARCH_HOSTS} "fleet-server") \
	ELASTICSEARCH_HOSTS=${TEST_ELASTICSEARCH_HOSTS} ELASTICSEARCH_USERNAME=${ELASTICSEARCH_USERNAME} ELASTICSEARCH_PASSWORD=${ELASTICSEARCH_PASSWORD} \
	AGENT_E2E_IMAGE=$(shell cat "build/e2e-image") \
	STANDALONE_E2E_IMAGE=$(DOCKER_IMAGE):$(DOCKER_IMAGE_TAG) \
	CGO_ENABLED=1 \
	go test -v -timeout 30m -tags=e2e,$(GOBUILDTAGS) -count=1 -race -p 1 ./...

##################################################
# Cloud testing targets
##################################################
.PHONY: test-cloude2e
test-cloude2e: prepare-test-context  ## - Run cloude2e tests with full setup (slow!)
	@# Triggered using a shell script to ensure deployment is cleaned up even if errors (using trap).
	@# it would also ensure to exit with failure if any error happens
	@$(CLOUD_TESTING_BASE)/launch_cloud_e2e_tests.sh

.PHONY: test-cloude2e-set
test-cloude2e-set: ## Run cloude2e test
	$(eval FLEET_SERVER_URL := $(shell make --no-print-directory -C ${CLOUD_TESTING_BASE} cloud-get-fleet-url))
	make -C ${CLOUD_TESTING_BASE} cloud-get-fleet-url
	FLEET_SERVER_URL="${FLEET_SERVER_URL}" go test -v -tags=cloude2e -count=1 -race -p 1 ./testing/cloude2e
