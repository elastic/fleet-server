#!/usr/bin/env bash

set -euo pipefail

GO_VERSION=$(cat .go-version)
SETUP_GVM_VERSION="v0.5.2"
PLATFORM_TYPE_LOWERCASE=$(uname | tr '[:upper:]' '[:lower:]')

export BIN=${WORKSPACE:-$PWD}/bin

CPU_ARCH=$(uname -m)
PLATFORM_TYPE=$(uname)

if [[ "${CPU_ARCH}" == "x86_64" ]]; then
  case "${PLATFORM_TYPE}" in
  Linux|Darwin)
    export GOX_FLAGS="-arch amd64"
    export GO_ARCH_TYPE="amd64"
    ;;
  MINGW*)
    export GOX_FLAGS="-arch 386"
    ;;
  esac
elif [[ "${CPU_ARCH}" == "aarch64" || "${CPU_ARCH}" == "arm64" ]]; then
  export GOX_FLAGS="-arch arm"
  export GO_ARCH_TYPE="arm64"
else
  echo "Unsupported OS"
  exit 1
fi

retry() {
  local retries=$1
  shift
  local count=0
  until "$@"; do
    exit=$?
    wait=$((2 ** count))
    count=$((count + 1))
    if [ $count -lt "$retries" ]; then
      >&2 echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
      sleep $wait
    else
      >&2 echo "Retry $count/$retries exited $exit, no more retries left."
      return $exit
    fi
  done
  return 0
}

create_workspace() {
  if [[ ! -d "${BIN}" ]]; then
    mkdir -p "${BIN}"
  fi
}

with_docker_compose() {
  echo "~~~ Setting up the Docker environment..."
  brew install docker colima
  export DOCKER_HOST="unix://$HOME/.colima/docker.sock"

  colima start --runtime docker
  if docker info >/dev/null 2>&1; then
    echo "Docker is running successfully via Colima!"
    docker --version
    colima status
  else
    echo "Docker did not start correctly. Please check the Colima logs."
    exit 1
  fi

  #  brew install docker-compose
  #  create_workspace
  #  retry 3 curl -sSL -o ${BIN}/docker-compose "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-${PLATFORM_TYPE_LOWERCASE}-${arch_type}"
  #  chmod +x ${BIN}/docker-compose
  #  export PATH="${BIN}:${PATH}"
  #  docker-compose version
}

add_bin_path() {
  echo "Adding PATH to the environment variables"
  create_workspace
  export PATH="${BIN}:${PATH}"
}

with_mage() {
  echo "~~~ Installing mage"
  create_workspace
  go install github.com/magefile/mage # uses go.mod implicitly
  mage -clean
  mage -version
  which mage
}

with_go() {
  echo "~~~ Setting up the Go environment"
  create_workspace
  retry 5 curl -sL -o "${BIN}/gvm" "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-${PLATFORM_TYPE_LOWERCASE}-${GO_ARCH_TYPE}"
  chmod +x "${BIN}/gvm"
  eval "$(gvm $GO_VERSION)"
  go version
  which go
  local go_path="$(go env GOPATH):$(go env GOPATH)/bin"
  export PATH="${go_path}:${PATH}"
}

add_bin_path
with_go "${GO_VERSION}"
with_mage
with_docker_compose

# prevent "OSError: [Errno 24] Too many open files" on macOS
ulimit -Sn 150000

mage test:e2e test:junitReport