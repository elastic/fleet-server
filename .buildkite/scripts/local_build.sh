#!/bin/bash

set -euo pipefail

source .buildkite/scripts/common.sh

add_bin_path
with_go

<<<<<<< HEAD
make local
=======
with_mage

mage build:local
>>>>>>> db5f46b (Convert Makefile to magefile.go (#4912))
