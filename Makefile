COMMIT=$(shell git rev-parse --short HEAD)
VERSION ?= $(shell head -n 1 VERSION 2> /dev/null || echo "0.0.0")
BUILD=$(shell date +%FT%T%z)
LDFLAGS=-w -s -X main.Version=${VERSION} -X main.Build=${BUILD}
PACKAGE_PATH=./dev-tools/package/
DOCKER_BUILD=@export DOCKER_CONTENT_TRUST=1 && export DOCKER_BUILDKIT=1 && docker build --build-arg COMMIT='$(COMMIT)' --build-arg VERSION='$(VERSION)' --build-arg LDFLAGS='$(LDFLAGS)' -f $(PACKAGE_PATH)Dockerfile

CMD_COLOR_ON=\033[32m\xE2\x9c\x93
CMD_COLOR_OFF=\033[0m

.PHONY: help
help: ## - Show help message
	@printf "${CMD_COLOR_ON} usage: make [target]\n\n${CMD_COLOR_OFF}"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | sed -e "s/^Makefile://" | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: rpm
rpm: ## - Build x86_64 linux RPM
	@printf "${CMD_COLOR_ON} Build rpm\n${CMD_COLOR_OFF}"
	@${DOCKER_BUILD} --ssh default  --target rpm -o ./  .

.PHONY: image
image:	## - Build the elastic fleet docker images
	@printf "${CMD_COLOR_ON} Build the elastic fleet docker image\n${CMD_COLOR_OFF}"
	${DOCKER_BUILD} --ssh default --target fleet -t fleet .

.PHONY: run
run: image ## - Run the smallest and secured golang docker image based on scratch
	@printf "${CMD_COLOR_ON} Run the elastic fleet docker image\n${CMD_COLOR_OFF}"
	@docker-compose -f ./dev-tools/package/docker-compose.yml up 


.PHONY: local
local: ## - Build packages using local environment
	@printf "${CMD_COLOR_ON} Build binaries using local go installation\n${CMD_COLOR_OFF}"
	go build -ldflags="${LDFLAGS}" -o ./bin/fleet .
	@printf "${CMD_COLOR_ON} Binaries in ./bin/\n${CMD_COLOR_OFF}"


.PHONY: clean
clean: ## - Clean up build artifacts
	@printf "${CMD_COLOR_ON} Clean up build artifacts\n${CMD_COLOR_OFF}"
	rm -rf ./bin/ *.rpm

.PHONY: generate
generate: ## - Generate schema models
	@printf "${CMD_COLOR_ON} Installing module for go generate\n${CMD_COLOR_OFF}"
	go install github.com/aleksmaus/generate/...
	@printf "${CMD_COLOR_ON} Running go generate\n${CMD_COLOR_OFF}"
	go generate ./...

.PHONY: check
check: ## - Run all checks
	@$(MAKE) generate
	@$(MAKE) check-headers
	@$(MAKE) check-go
	@$(MAKE) check-no-changes

.PHONY: check-headers
check-headers:  ## - Check copyright headers
	@go install github.com/elastic/go-licenser
	@go-licenser -license Elastic

.PHONY: check-go
check-go: ## - Run go fmt, go vet, go mod tidy
	@go fmt ./...
	@go vet ./...
	@go mod tidy

.PHONY: check-no-changes
check-no-changes:
	@git diff | cat
	@git update-index --refresh
	@git diff-index --exit-code HEAD --

.PHONY: test
test:  ## - Run all tests
	@mkdir -p build
	@$(MAKE) test-unit 
	# @$(MAKE) test-int
	@$(MAKE) junit-report

.PHONY: test-unit 
test-unit: ## - Run unit tests only
	@go test -v -race ./... | tee build/test-unit.out

.PHONY: junit-report
junit-report: ## - Run the junit-report generation for all the out files generated
	@go get -v -u github.com/jstemmer/go-junit-report
	$(foreach file, $(wildcard build/*.out), go-junit-report > "${file}.xml" < ${file};)

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
test-int: ## - Run integration tests with full setup (slow!)
	@$(MAKE) int-docker-start
	@$(MAKE) test-int-set | tee build/test-init.out
	@$(MAKE) int-docker-stop

# Run integration tests without starting/stopping docker
# Useful for development where you:
# 1. Start integration environment
# 2. Develop/test/repeat
# 3  Stop integration environment when done
.PHONY: test-int-set
test-int-set: ## - Run integration tests without setup
	# Initialize indices one before running all the tests
	ELASTICSEARCH_HOSTS=${TEST_ELASTICSEARCH_HOSTS} go run ./dev-tools/integration/main.go
	ELASTICSEARCH_HOSTS=${TEST_ELASTICSEARCH_HOSTS} go test -v -tags=integration -count=1 -race ./...
