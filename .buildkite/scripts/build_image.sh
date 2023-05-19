#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

trap docker_logout EXIT

.buildkite/scripts/imageprep.sh build-image
.buildkite/scripts/imageprep.sh push-image
.buildkite/scripts/imageprep.sh retag-and-push-image
