#!/bin/bash

host="$1"

jsonBody="$(curl -sSL -XPOST "$host/_security/service/elastic/fleet-server/credential/token/token1")"

# use grep and sed to get the service token value as we may not have jq or a similar tool on the instance
token=$(echo ${jsonBody} |  grep -Eo '"value"[^}]*' | grep -Eo ':.*' | sed -r "s/://" | sed -r 's/"//g')

# cache or use cached token in order to be able to run repeative integration tests,
# very useful during development, without recreating elasticsearch instance every time.
if [ -z "$token" ]
then
    token=`cat .service_token` 
else
    echo "$token" > .service_token
fi

echo $token
