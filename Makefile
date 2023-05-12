SHELL=/usr/bin/env bash
GO_VERSION=$(shell cat '.go-version')
DEFAULT_VERSION=$(shell awk '/const DefaultVersion/{print $$NF}' version/version.go | tr -d '"')
TARGET_ARCH_386=x86
TARGET_ARCH_amd64=x86_64
TARGET_ARCH_arm64=arm64
PLATFORMS ?= darwin/amd64 darwin/arm64 linux/386 linux/amd64 linux/arm64 windows/386 windows/amd64
BUILDMODE_linux_amd64=-buildmode=pie
BUILDMODE_linux_arm64=-buildmode=pie
BUILDMODE_windows_386=-buildmode=pie
BUILDMODE_windows_amd64=-buildmode=pie
BUILDMODE_darwin_amd64=-buildmode=pie
BUILDMODE_darwin_arm64=-buildmode=pie

BUILDER_IMAGE=docker.elastic.co/beats-dev/golang-crossbuild:${GO_VERSION}-main-debian11

#Benchmark related targets
BENCH_BASE ?= benchmark-$(COMMIT).out
BENCH_NEXT ?=
BENCHMARK_ARGS := -count=8
BENCHMARK_PACKAGE ?= ./...
BENCHMARK_FILTER ?= Bench

GO_TEST_FLAG = ""
ifdef TEST_COVERAGE
GO_TEST_FLAG = -covermode=atomic -coverprofile=build/TEST-go-fleet-server-coverage.cov --jsonfile build/TEST-go-fleet-server-test.json
endif

#Cloud testing env target
CLOUD_TESTING_BASE=./dev-tools/cloud

ifdef VERSION_QUALIFIER
DEFAULT_VERSION:=${DEFAULT_VERSION}-${VERSION_QUALIFIER}
endif

ifeq ($(SNAPSHOT),true)
VERSION=${DEFAULT_VERSION}-SNAPSHOT
else
VERSION=${DEFAULT_VERSION}
endif

DOCKER_IMAGE_TAG?=${VERSION}
DOCKER_IMAGE?=docker.elastic.co/fleet-server/fleet-server


PLATFORM_TARGETS=$(addprefix release-, $(PLATFORMS))
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

.PHONY: help
help: ## - Show help message
	@printf "${CMD_COLOR_ON} usage: make [target]\n\n${CMD_COLOR_OFF}"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | sed -e "s/^Makefile://" | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: list-platforms
list-platforms: ## - Show the possible PLATFORMS
	@echo  "${PLATFORMS}"

.PHONY: local
local: ## - Build local binary for local environment (bin/fleet-server)
	@printf "${CMD_COLOR_ON} Build binaries using local go installation\n${CMD_COLOR_OFF}"
	go build $(if $(DEV),-tags="dev",) -gcflags="${GCFLAGS}" -ldflags="${LDFLAGS}" -o ./bin/fleet-server .
	@printf "${CMD_COLOR_ON} Binaries in ./bin/\n${CMD_COLOR_OFF}"

.PHONY: clean
clean: ## - Clean up build artifacts
	@printf "${CMD_COLOR_ON} Clean up build artifacts\n${CMD_COLOR_OFF}"
	rm -rf .service_token ./bin/ ./build/

.PHONY: generate
generate: ## - Generate schema models
	@printf "${CMD_COLOR_ON} Installing module for go generate\n${CMD_COLOR_OFF}"
	env GOBIN=${GOBIN} go install github.com/elastic/go-json-schema-generate/cmd/schema-generate@ec19b88f6b5ef7825a928df8274a99337b855d1f
	@printf "${CMD_COLOR_ON} Installing module for oapi-codegen\n${CMD_COLOR_OFF}"
	env GOBIN=${GOBIN} go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest
	@printf "${CMD_COLOR_ON} Running go generate\n${CMD_COLOR_OFF}"
	env PATH="${GOBIN}:${PATH}" go generate ./...

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
	@env GOBIN=${GOBIN} go install github.com/elastic/go-licenser@latest
	@env PATH="${GOBIN}:${PATH}" go-licenser -license Elastic

.PHONY: check-go
check-go: ## - Run golangci-lint
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/d58dbde584c801091e74a00940e11ff18c6c68bd/install.sh | sh -s v1.51.1
	@./bin/golangci-lint run -v

.PHONY: notice
notice: ## - Generates the NOTICE.txt file.
	@echo "Generating NOTICE.txt"
	@go mod tidy
	@go mod download all
	@env GOBIN=${GOBIN} go install go.elastic.co/go-licence-detector@latest
	go list -m -json all | env PATH="${GOBIN}:${PATH}" go-licence-detector \
		-includeIndirect \
		-rules dev-tools/notice/rules.json \
		-overrides dev-tools/notice/overrides.json \
		-noticeTemplate dev-tools/notice/NOTICE.txt.tmpl \
		-noticeOut NOTICE.txt \
		-depsOut ""

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
	./.ci/scripts/test-release.sh $(DEFAULT_VERSION)

.PHONY: test-unit
test-unit: prepare-test-context  ## - Run unit tests only
	set -o pipefail; go test ${GO_TEST_FLAG} -v -race ./... | tee build/test-unit.out

.PHONY: benchmark
benchmark: prepare-test-context install-benchstat  ## - Run benchmark tests only
	set -o pipefail; go test -bench=$(BENCHMARK_FILTER) -run=$(BENCHMARK_FILTER) $(BENCHMARK_ARGS) $(BENCHMARK_PACKAGE) | tee "build/$(BENCH_BASE)"

.PHONY: install-benchstat
install-benchstat: ## - Install the benchstat package
	@benchstat 2> /dev/null || go install golang.org/x/perf/cmd/benchstat@latest

.PHONY: benchstat
benchstat: install-benchstat ## - Run the benchstat comparing base against next, BENCH_BASE and BENCH_NEXT are required for comparison
	$(eval BENCHSTAT_ARGS := "build/$(BENCH_BASE)")
ifneq ($(BENCH_NEXT),)
	$(eval BENCHSTAT_ARGS += "build/$(BENCH_NEXT)")
endif
	@benchstat $(BENCHSTAT_ARGS)

.PHONY: prepare-test-context
prepare-test-context: ## - Prepare the test context folders
	@mkdir -p build

.PHONY: junit-report
junit-report: ## - Run the junit-report generation for all the out files generated
	@go install github.com/jstemmer/go-junit-report@latest
	$(foreach file, $(wildcard build/*.out), go-junit-report > "${file}.xml" < ${file};)

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
	GOOS=$($@_OS) GOARCH=$($@_GO_ARCH) go build $(if $(DEV),-tags="dev",) -gcflags="${GCFLAGS}" -ldflags="${LDFLAGS}" $($@_BUILDMODE) -o build/binaries/fleet-server-$(VERSION)-$($@_OS)-$($@_ARCH)/fleet-server .
	@$(MAKE) OS=$($@_OS) ARCH=$($@_ARCH) package-target

.PHONY: build-docker
build-docker:
	docker build \
		--build-arg GO_VERSION=$(GO_VERSION) \
		--build-arg=GCFLAGS="${GCFLAGS}" \
		--build-arg=LDFLAGS="${LDFLAGS}" \
		--build-arg=DEV="$(DEV)" \
		--build-arg=VERSION="$(VERSION)" \
		-t $(DOCKER_IMAGE):$(DOCKER_IMAGE_TAG)$(if $(DEV),-dev,) .

.PHONY: release-docker
release-docker:
	docker push \
		$(DOCKER_IMAGE):$(DOCKER_IMAGE_TAG)$(if $(DEV),-dev,)

.PHONY: package-target
package-target: build/distributions
ifeq ($(OS),windows)
	@mv build/binaries/fleet-server-$(VERSION)-$(OS)-$(ARCH)/fleet-server build/binaries/fleet-server-$(VERSION)-$(OS)-$(ARCH)/fleet-server.exe
	@cd build/binaries && zip -q -r ../distributions/fleet-server-$(VERSION)-$(OS)-$(ARCH).zip fleet-server-$(VERSION)-$(OS)-$(ARCH)
	@cd build/distributions && shasum -a 512 fleet-server-$(VERSION)-$(OS)-$(ARCH).zip > fleet-server-$(VERSION)-$(OS)-$(ARCH).zip.sha512
else ifeq ($(OS)-$(ARCH),darwin-arm64)
	@mv build/binaries/fleet-server-$(VERSION)-$(OS)-$(ARCH) build/binaries/fleet-server-$(VERSION)-$(OS)-aarch64
	@tar -C build/binaries -zcf build/distributions/fleet-server-$(VERSION)-$(OS)-aarch64.tar.gz fleet-server-$(VERSION)-$(OS)-aarch64
	@cd build/distributions && shasum -a 512 fleet-server-$(VERSION)-$(OS)-aarch64.tar.gz > fleet-server-$(VERSION)-$(OS)-aarch64.tar.gz.sha512
else
	@tar -C build/binaries -zcf build/distributions/fleet-server-$(VERSION)-$(OS)-$(ARCH).tar.gz fleet-server-$(VERSION)-$(OS)-$(ARCH)
	@cd build/distributions && shasum -a 512 fleet-server-$(VERSION)-$(OS)-$(ARCH).tar.gz > fleet-server-$(VERSION)-$(OS)-$(ARCH).tar.gz.sha512
endif

build-releaser: ## - Build a Docker image to run make package including all build tools
	docker build -t $(BUILDER_IMAGE) -f Dockerfile.build --build-arg GO_VERSION=$(GO_VERSION) .

.PHONY: docker-release
docker-release: build-releaser ## - Builds a release for all platforms in a dockerised environment
	docker run --rm -u $(shell id -u):$(shell id -g) --volume $(PWD):/go/src/github.com/elastic/fleet-server $(BUILDER_IMAGE)

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
	@echo $(DEFAULT_VERSION)

##################################################
# Integration testing targets
##################################################

# Load environment (ES version and creds)
include ./dev-tools/integration/.env
export $(shell sed 's/=.*//' ./dev-tools/integration/.env)

# Start ES with docker without waiting
.PHONY: int-docker-start-async
int-docker-start-async:
	@docker-compose -f ./dev-tools/integration/docker-compose.yml --env-file ./dev-tools/integration/.env up  -d --remove-orphans elasticsearch

# Wait for ES to be ready
.PHONY: int-docker-wait
int-docker-wait:
	@./dev-tools/integration/wait-for-elasticsearch.sh ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}@${TEST_ELASTICSEARCH_HOSTS}

# Start integration docker setup with wait for when the ES is ready
.PHONY: int-docker-start
int-docker-start: ## - Start docker envronment for integration tests and wait until it's ready
	@$(MAKE) int-docker-start-async
	@$(MAKE) int-docker-wait

# Stop integration docker setup
.PHONY: int-docker-stop
int-docker-stop: ## - Stop docker environment for integration tests
	@docker-compose -f ./dev-tools/integration/docker-compose.yml --env-file ./dev-tools/integration/.env down

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
	ELASTICSEARCH_SERVICE_TOKEN=$(shell ./dev-tools/integration/get-elasticsearch-servicetoken.sh ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}@${TEST_ELASTICSEARCH_HOSTS}) \
	ELASTICSEARCH_HOSTS=${TEST_ELASTICSEARCH_HOSTS} ELASTICSEARCH_USERNAME=${ELASTICSEARCH_USERNAME} ELASTICSEARCH_PASSWORD=${ELASTICSEARCH_PASSWORD} \
	go test -v -tags=integration -count=1 -race -p 1 ./...

##################################################
# Cloud testing targets
##################################################
.PHONY: test-cloude2e
test-cloude2e: prepare-test-context  ## - Run cloude2e tests with full setup (slow!)
	@make -C ${CLOUD_TESTING_BASE} cloud-deploy
	$(eval FLEET_SERVER_URL := $(shell make -C ${CLOUD_TESTING_BASE} cloud-get-fleet-url))
	-@set -o pipefail; $(MAKE) test-cloude2e-set | tee build/test-cloude2e.out
	@make -C ${CLOUD_TESTING_BASE} cloud-clean

.PHONY: test-cloude2e-set
test-cloude2e-set: ## Run cloude2e test
	$(eval FLEET_SERVER_URL := $(shell make -C ${CLOUD_TESTING_BASE} cloud-get-fleet-url))
	make -C ${CLOUD_TESTING_BASE} cloud-get-fleet-url
	FLEET_SERVER_URL=${FLEET_SERVER_URL} go test -v -tags=cloude2e -count=1 -race -p 1 ./testing/cloude2e
