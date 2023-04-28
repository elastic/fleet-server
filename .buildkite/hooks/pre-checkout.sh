#!/bin/bash

set -euo pipefail

# Configure local git to access PR reflog
git config remote.origin.fetch '+refs/pull/*:refs/remotes/origin/pull/*'
