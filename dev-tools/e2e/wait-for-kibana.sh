#!/bin/bash

set -e

host="$1"
shift
cmd="$@"


until $(curl --output /dev/null --silent --head --fail "${host}/api/status"); do
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
