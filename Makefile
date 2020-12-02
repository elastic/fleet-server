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
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


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
check:
	@$(MAKE) generate
	@$(MAKE) check-headers
	@$(MAKE) check-go
	@$(MAKE) check-no-changes

.PHONY: check-headers
check-headers:
	@go install github.com/elastic/go-licenser
	@go-licenser -license Elastic

.PHONY: check-go
check-go:
	@go fmt ./...
	@go vet ./...
	@go mod tidy

.PHONY: check-no-changes
check-no-changes:
	@git diff | cat
	@git update-index --refresh
	@git diff-index --exit-code HEAD --

.PHONY: test
test: ## - Run some tests
	@go test -race ./...
