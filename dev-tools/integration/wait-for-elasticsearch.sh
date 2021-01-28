#!/bin/bash

set -e

host="$1"
shift
cmd="$@"


until $(curl --output /dev/null --silent --head --fail "$host"); do
    printf '.'
    sleep 1
done

# First wait for ES to start...
response=$(curl $host)

until [ "$response" = "200" ]; do
    response=$(curl --write-out %{http_code} --silent --output /dev/null "$host")
    echo '.'
    sleep 1
done


# next wait for ES status to turn to green
health="$(curl -fsSL "$host/_cat/health?h=status")"
health="$(echo "$health" | tr -d '[:space:]')"

until [ "$health" = 'green' ]; do
    health="$(curl -fsSL "$host/_cat/health?h=status")"
    echo $health
    health="$(echo "$health" | tr -d '[:space:]')"
    >&2 echo "Elasticsearch is unavailable - sleeping"
    sleep 1
done

>&2 echo "Elasticsearch is up"
exec $cmd