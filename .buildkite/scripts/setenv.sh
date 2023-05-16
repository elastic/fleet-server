#!/bin/bash

set -euo pipefail

source ./buildkite/scripts/common.sh

MESSAGE="Usage: $0 <option>. Examples: "$0 with-go" or "$0 with-docker-compose" or "$0 with-go-docker-compose" "

if [ $# -lt 1 ]; then
  echo "${MESSAGE}"
  exit 1
fi

option=$1

case $option in
  "with-go")
    echo "Setting up Go environment..."
    add_bin_path
    with_go
    ;;
  "with-docker-compose")
    echo "Setting up Docker-compose environment..."
    add_bin_path
    with_docker_compose
    ;;
  "with-go-docker-compose")
    echo "Setting up Docker-compose and GO environments..."
    add_bin_path
    with_go
    with_docker_compose
    ;;
  *)
    echo -e "Unexpected input: $option.\n"${MESSAGE}""
    exit 1
    ;;
esac
