#!/bin/bash

set -e

host="$1"

jsonBody="$(curl -fsSL -XPOST "$host/_security/service/elastic/fleet-server/credential/token/token1")"
# use grep and sed to get the service token value as we may not have jq or a similar tool on the instance
token=$(echo ${jsonBody} |  grep -Eo '"value"[^}]*' | grep -Eo ':.*' | sed -r "s/://" | sed -r 's/"//g')
echo $token
