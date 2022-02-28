SHELL=/usr/bin/env bash
GO_VERSION=$(shell cat '.go-version')
DEFAULT_VERSION=$(shell awk '/const defaultVersion/{print $$NF}' main.go | tr -d '"')
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

BUILDER_IMAGE=docker.elastic.co/observability-ci/fleet-server-builder:latest

ifdef VERSION_QUALIFIER
DEFAULT_VERSION:=${DEFAULT_VERSION}-${VERSION_QUALIFIER}
endif

ifeq ($(SNAPSHOT),true)
VERSION=${DEFAULT_VERSION}-SNAPSHOT
else
VERSION=${DEFAULT_VERSION}
endif

PLATFORM_TARGETS=$(addprefix release-, $(PLATFORMS))
COMMIT=$(shell git rev-parse --short HEAD)
NOW=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-w -s -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=$(NOW)
CMD_COLOR_ON=\033[32m\xE2\x9c\x93
CMD_COLOR_OFF=\033[0m

# Directory to dump build tools into
GOBIN=$(shell go env GOPATH)/bin/

.PHONY: help
help: ## - Show help message
	@printf "${CMD_COLOR_ON} usage: make [target]\n\n${CMD_COLOR_OFF}"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | sed -e "s/^Makefile://" | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: local
local: ## - Build local binary for local environment (bin/fleet-server)
	@printf "${CMD_COLOR_ON} Build binaries using local go installation\n${CMD_COLOR_OFF}"
	go build -ldflags="${LDFLAGS}" -o ./bin/fleet-server .
	@printf "${CMD_COLOR_ON} Binaries in ./bin/\n${CMD_COLOR_OFF}"

.PHONY: clean
clean: ## - Clean up build artifacts
	@printf "${CMD_COLOR_ON} Clean up build artifacts\n${CMD_COLOR_OFF}"
	rm -rf ./bin/ ./build/
	rm .service_token

.PHONY: generate
generate: ## - Generate schema models
	@printf "${CMD_COLOR_ON} Installing module for go generate\n${CMD_COLOR_OFF}"
	env GOBIN=${GOBIN} go install github.com/aleksmaus/generate/cmd/schema-generate@5672148f3c31d78bbd0124583bc20133f2e18f37
	@printf "${CMD_COLOR_ON} Running go generate\n${CMD_COLOR_OFF}"
	env PATH="${GOBIN}:${PATH}" go generate ./...

.PHONY: check-ci
check-ci: ## - Run all checks of the ci without linting, the linter is run through github action to have comments in the pull-request.
	@$(MAKE) generate
	@$(MAKE) defaults
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
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/d58dbde584c801091e74a00940e11ff18c6c68bd/install.sh | sh -s v1.44.2
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

.PHONY: defaults
defaults: ## -Generate defaults based on limits files.
	@echo "Generating env_defaults.go"
	@go run dev-tools/buildlimits/buildlimits.go --in "internal/pkg/config/defaults/*.yml" --out internal/pkg/config/env_defaults.go

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
	set -o pipefail; go test -v -race ./... | tee build/test-unit.out

.PHONY: prepare-test-context
prepare-test-context: ## - Prepare the test context folders
	@mkdir -p build

.PHONY: junit-report
junit-report: ## - Run the junit-report generation for all the out files generated
	@go get -v -u github.com/jstemmer/go-junit-report
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
	GOOS=$($@_OS) GOARCH=$($@_GO_ARCH) go build -ldflags="${LDFLAGS}" $($@_BUILDMODE) -o build/binaries/fleet-server-$(VERSION)-$($@_OS)-$($@_ARCH)/fleet-server .
	@$(MAKE) OS=$($@_OS) ARCH=$($@_ARCH) package-target

.PHONY: package-target
package-target: build/distributions
ifeq ($(OS),windows)
	@mv build/binaries/fleet-server-$(VERSION)-$(OS)-$(ARCH)/fleet-server build/binaries/fleet-server-$(VERSION)-$(OS)-$(ARCH)/fleet-server.exe
	@cd build/binaries && zip -q -r ../distributions/fleet-server-$(VERSION)-$(OS)-$(ARCH).zip fleet-server-$(VERSION)-$(OS)-$(ARCH)
	@cd build/distributions && shasum -a 512 fleet-server-$(VERSION)-$(OS)-$(ARCH).zip > fleet-server-$(VERSION)-$(OS)-$(ARCH).zip.sha512
else
	@tar -C build/binaries -zcf build/distributions/fleet-server-$(VERSION)-$(OS)-$(ARCH).tar.gz fleet-server-$(VERSION)-$(OS)-$(ARCH)
	@cd build/distributions && shasum -a 512 fleet-server-$(VERSION)-$(OS)-$(ARCH).tar.gz > fleet-server-$(VERSION)-$(OS)-$(ARCH).tar.gz.sha512
endif

build-releaser: ## - Build a Docker image to run make package including all build tools
	docker build -t $(BUILDER_IMAGE) -f Dockerfile.build --build-arg GO_VERSION=$(GO_VERSION) .

.PHONY: docker-release
docker-release: build-releaser ## - Builds a release for all platforms in a dockerised environment
	docker run --rm --volume $(PWD):/go/src/github.com/elastic/fleet-server $(BUILDER_IMAGE)

.PHONY: release
release: $(PLATFORM_TARGETS) ## - Builds a release. Specify exact platform with PLATFORMS env.

.PHONY: release-manager-snapshot
release-manager-snapshot: ## - Builds a snapshot release. The Go version defined in .go-version will be installed and used for the build.
	@$(MAKE) SNAPSHOT=true release-manager-release

.PHONY: release-manager-release
release-manager-release: ## - Builds a snapshot release. The Go version defined in .go-version will be installed and used for the build.
	./dev-tools/run_with_go_ver $(MAKE) release

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
