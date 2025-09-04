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
  echo "~~~ brew update"
  export HOMEBREW_NO_INSTALL_CLEANUP=1
  export HOMEBREW_QUIET=1
  brew update --auto-update

  echo "~~~ install tools"
  brew install docker docker-buildx docker-compose
  brew install colima lima coreutils

#  brew install colima qemu coreutils

#  echo "~~~ colima start: qemu"
#  colima start --vm-type=qemu --cpu 4 --memory 4 --disk 20 > /dev/null

  echo "~~~ macos version: $(sw_vers)"
  echo "~~~ virtualization"
  sysctl -a | grep kern.hv
  sysctl hw.optional.arm64
  sysctl kern.hv_vmm_present
  echo "~~~ colima version: $(brew info colima)"
  echo "~~~ lima version: $(brew info lima)"
#  echo "~~~ limactl version: $(limactl info)"

  brew upgrade lima
  brew upgrade colima

  colima stop || true
  colima delete default --force || true
  colima delete --force || true

  rm -rf ~/.colima || true
  rm -rf ~/.colima/_lima || true
  rm -rf ~/.lima || true

  limactl start template://docker
  export DOCKER_HOST=$(limactl list docker --format 'unix://{{.Dir}}/sock/docker.sock')
  docker run --rm hello-world
  limactl stop

  local retryCount=3
  local try=1
  local sleep=5

  while [ "$try" -le "$retryCount" ]; do
    echo "~~~ start colima: try $try of $retryCount tries"

    local logfile="runlogs-$try"

    touch "$logfile"
    colima start --vm-type=vz  --arch aarch64 --network-address --cpu 2 --memory 2 --disk 20 -v > "$logfile" && break

    echo "~~~ Logfile"
    cat "$logfile"
#    colima start --vm-type=vz --network-address --cpu 4 --memory 4 --disk 20 && break
#    colima start --vm-type=vz --network-address --cpu 4 --memory 4 --disk 20 > /dev/null && break
#    colima start --vm-type=qemu --cpu 4 --memory 4 --disk 20 > /dev/null && break

    echo "~~~ ha.stderr.log"
    cat ~/.colima/_lima/colima/ha.stderr.log

    echo "colima failed, will retry"
    try=$((try + 1))
    sleep "$sleep"
  done

  if [ "$try" -gt "$retryCount" ]; then
    echo "colima couldn't start"
    exit 1
  fi

  echo "~~~ wait"
  gtimeout 60 bash -c 'while ! docker system info > /dev/null 2>&1; do echo "~~~ Waiting for Colima..."; sleep 3; done' || {
    echo "colima failed to init"
    exit 1
  }
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

# prevent "OSError: [Errno 24] Too many open files" on macOS
ulimit -Sn 150000

#add_bin_path
#with_go "${GO_VERSION}"
#with_mage

with_docker_compose

#echo "~~~ Running E2E tests"
#mage test:e2e test:junitReport