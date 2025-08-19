#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)/bin"
TMP_FOLDER_TEMPLATE_BASE="tmp.fleet-server"
REPO="fleet-server"
platform_type="$(uname)"
platform_type_lowercase="${platform_type,,}"
hw_type="$(uname -m)"

check_platform_architeture() {
# for downloading the GVM and Terraform packages
  case "${hw_type}" in
   "x86_64")
        arch_type="amd64"
        ;;
    "aarch64")
        arch_type="arm64"
        ;;
    "arm64")
        arch_type="arm64"
        ;;
    *)
    echo "The current platform/OS type is unsupported yet"
    ;;
  esac
}

create_workspace() {
    if [[ ! -d "${WORKSPACE}" ]]; then
    mkdir -p ${WORKSPACE}
    fi
}

add_bin_path() {
    echo "Adding PATH to the environment variables..."
    create_workspace
    export PATH="${PATH}:${WORKSPACE}"
}

with_go() {
    echo "Setting up the Go environment..."
    create_workspace
    check_platform_architeture
    retry 5 curl -sL -o ${WORKSPACE}/gvm "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-${platform_type_lowercase}-${arch_type}"
    chmod +x ${WORKSPACE}/gvm
    eval "$(gvm $(cat .go-version))"
    go version
    which go
    export PATH="${PATH}:$(go env GOPATH):$(go env GOPATH)/bin"
}

with_docker_compose() {
    echo "Setting up the Docker-compose environment..."
    create_workspace
    retry 5 curl -sSL -o ${WORKSPACE}/docker-compose "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-${platform_type_lowercase}-${hw_type}"
    chmod +x ${WORKSPACE}/docker-compose
    docker-compose version
}

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

docker_logout() {
    echo "Logging out from Docker..."
    docker logout ${DOCKER_REGISTRY}
}

with_Terraform() {
    echo "Setting up the Terraform environment..."
    local path_to_file="${WORKSPACE}/terraform.zip"
    create_workspace
    check_platform_architeture
    retry 5 curl -sSL -o ${path_to_file} "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_${platform_type_lowercase}_${arch_type}.zip"
    unzip -q ${path_to_file} -d ${WORKSPACE}/
    rm ${path_to_file}
    chmod +x ${WORKSPACE}/terraform
    terraform version
}

fix_gsutil() {
    # Decide if we need to replace a non-working gsutil (e.g. when it requires Python 3.9 on an old distro like Ubuntu 20.04) with a snap version
    if gsutil --version >/dev/null 2>&1; then
        echo "--- gsutil works; nothing to do."
    else
        echo "--- Installing gsutil via snap and removing old installs..."
        # Remove apt-based Cloud SDKs if present
        sudo apt-get update || true
        sudo DEBIAN_FRONTEND=noninteractive apt-get -y purge google-cloud-cli google-cloud-sdk || true

        # Remove common archive-install locations and stray shims
        sudo rm -rf /opt/google-cloud-sdk /usr/lib/google-cloud-sdk || true
        sudo rm -f /usr/bin/gsutil /usr/local/bin/gsutil /usr/bin/gcloud /usr/local/bin/gcloud || true

        SDK_DIR="/opt/google-cloud-sdk"
        VENV="/opt/gcloud-py"
        CONFIG_DIR="/opt/buildkite-agent/.config/gcloud"
        
        # Set architecture-specific archive URL
        check_platform_architeture
        case "${arch_type}" in
            "amd64")
                ARCHIVE_URL="https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz"
                ;;
            "arm64")
                ARCHIVE_URL="https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-arm.tar.gz"
                ;;
            *)
                echo "Unsupported architecture: ${arch_type}"
                return 1
                ;;
        esac

        # Ensure config dir exists and is writable by the current user
        sudo mkdir -p "$CONFIG_DIR"
        sudo chown -R "$(id -u)":"$(id -g)" "$CONFIG_DIR"

        # Install a modern Python alongside (3.10) -- this doesn't affect the system Python
        sudo apt-get update -y
        sudo apt-get install -y software-properties-common curl ca-certificates gnupg
        if ! command -v python3.10 >/dev/null 2>&1; then
        sudo add-apt-repository -y ppa:deadsnakes/ppa
        sudo apt-get update -y
        sudo apt-get install -y python3.10 python3.10-venv
        fi

        if [[ ! -d "$VENV" ]]; then
        sudo python3.10 -m venv "$VENV"
        sudo "$VENV/bin/python" -m pip install --upgrade pip
        fi

        # Install the Cloud SDK from tarball (no system Python dependency)
        if [[ ! -d "$SDK_DIR" ]]; then
        curl -fsSLo /tmp/google-cloud-cli.tar.gz "$ARCHIVE_URL"
        sudo tar -C /opt -xzf /tmp/google-cloud-cli.tar.gz
        sudo /opt/google-cloud-sdk/install.sh --quiet
        fi

        # Make it work NOW in this shell
        export CLOUDSDK_PYTHON="$VENV/bin/python"
        export CLOUDSDK_CONFIG="$CONFIG_DIR"
        export PATH="/opt/google-cloud-sdk/bin:$PATH"
        hash -r || true

        # Persist for future shells (all users)
        sudo tee /etc/profile.d/gcloud.sh >/dev/null <<EOF
        # Google Cloud CLI env
        export CLOUDSDK_PYTHON="$VENV/bin/python"
        export CLOUDSDK_CONFIG="$CONFIG_DIR"
        case ":\$PATH:" in *:/opt/google-cloud-sdk/bin:*) ;; *) export PATH="/opt/google-cloud-sdk/bin:\$PATH";; esac
        EOF
        sudo chmod 644 /etc/profile.d/gcloud.sh

        # 5) Handy symlinks (works even if some shells ignore /etc/profile.d)
        for b in gcloud gsutil bq; do
        sudo ln -sf "/opt/google-cloud-sdk/bin/\$b" "/usr/local/bin/\$b"
        done

        echo "[ok] gsutil at: $(command -v gsutil)"
        gsutil --version



        sudo apt-get update
        sudo apt-get install -y software-properties-common curl
        sudo add-apt-repository -y ppa:deadsnakes/ppa
        sudo apt-get update
        sudo apt-get install -y python3.9 python3.9-venv python3.9-distutils

        # Optional but tidy: put Cloud SDK on its own venv
        sudo python3.9 -m venv /opt/gcloud-py
        sudo /opt/gcloud-py/bin/python -m pip install --upgrade pip

        # Get the ARM64 Cloud SDK archive and install
        curl -fsSLO https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-arm.tar.gz
        sudo tar -C /opt -xzf google-cloud-cli-linux-arm.tar.gz
        sudo /opt/google-cloud-sdk/install.sh --quiet

        # Make the SDK use your private Python, and add to PATH
        sudo tee /etc/profile.d/gcloud.sh >/dev/null <<'EOF'
        export CLOUDSDK_PYTHON=/opt/gcloud-py/bin/python
        . /opt/google-cloud-sdk/path.bash.inc
EOF

        # Verify (new shell or source the file)
        source /etc/profile.d/gcloud.sh
        gsutil version -l


        echo "--- gsutil installed at: $(command -v gsutil)"
        gsutil version -l
    fi
}

google_cloud_auth() {
    local secretFileLocation=$(mktemp -d -p "${WORKSPACE}" -t "${TMP_FOLDER_TEMPLATE_BASE}.XXXXXXXXX")/google-cloud-credentials.json
    echo "${PRIVATE_CI_GCS_CREDENTIALS_SECRET}" > ${secretFileLocation}
    gcloud auth activate-service-account --key-file ${secretFileLocation} 2> /dev/null
    export GOOGLE_APPLICATION_CREDENTIALS=${secretFileLocation}
}

upload_packages_to_gcp_bucket() {
    local pattern=${1}
    local baseUri="gs://${JOB_GCS_BUCKET}/${REPO}"
    local bucketUriCommit="${baseUri}/commits/${BUILDKITE_COMMIT}"
    local bucketUriDefault="${baseUri}/snapshots"

    if [[ ${BUILDKITE_PULL_REQUEST} != "false" ]]; then
        bucketUriDefault="${baseUri}/pull-requests/pr-${GITHUB_PR_NUMBER}"
    fi
    for bucketUri in "${bucketUriCommit}" "${bucketUriDefault}"; do
        gsutil -m -q cp -r ${pattern} "${bucketUri}"
    done
}

get_bucket_uri() {
    local type=${1}
    local baseUri="gs://${JOB_GCS_BUCKET}/jobs"
    if [[ ${type} == "snapshot" ]]; then
        local folder="commits"
    else
        local folder="${type}"
    fi
    bucketUri="${baseUri}/${folder}/${BUILDKITE_COMMIT}"
}

upload_mbp_packages_to_gcp_bucket() {
    local pattern=${1}
    local type=${2}
    get_bucket_uri "${type}"
    gsutil -m -q cp -r ${pattern} ${bucketUri}
}

download_mbp_packages_from_gcp_bucket() {
    local pattern=${1}
    local type=${2}
    mkdir -p ${WORKSPACE}/${pattern}
    get_bucket_uri "${type}"
    gsutil -m -q cp -r ${bucketUri}/* ${WORKSPACE}/${pattern}
}

with_mage() {
    local install_packages=(
            "github.com/magefile/mage"
            "github.com/elastic/go-licenser"
            "golang.org/x/tools/cmd/goimports"
            "github.com/jstemmer/go-junit-report"
            "gotest.tools/gotestsum"
    )
    create_workspace
    for pkg in "${install_packages[@]}"; do
        go install "${pkg}@latest"
    done
}

cleanup() {
    echo "Deleting temporary files..."
    rm -rf ${WORKSPACE}/${TMP_FOLDER_TEMPLATE_BASE}.*
    echo "Done."
}