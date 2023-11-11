#!/bin/bash

set -e

host="$1"
shift
cmd="$@"

REPO_ROOT=$(cd $(dirname $(readlink -f "$0"))/../.. && pwd)

until $(curl --output /dev/null --silent --head --fail "${host}/api/status"); do
    if [[ ! $(docker compose  -f $REPO_ROOT/dev-tools/e2e/docker-compose.yml --env-file $REPO_ROOT/dev-tools/integration/.env ps  --filter status=running -q  kibana 2>/dev/null) ]]; then
        echo "Kibana container is not running"
        docker-compose -f $REPO_ROOT/dev-tools/e2e/docker-compose.yml --env-file $REPO_ROOT/dev-tools/integration/.env logs kibana
        exit 1
    fi
    printf '.'
    sleep 1
done

# First wait for ES to start...
response=$(curl $host)

until [ "$response" = "200" ]; do
    response=$(curl --write-out %{http_code} --silent --output /dev/null "${host}/api/status")
    echo '.'
    sleep 1
done

>&2 echo "Kibana is up"
exec $cmd
