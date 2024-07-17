#!/bin/bash

host="$1"

jsonBody=$(curl -sSL -XPOST "$host/_security/api_key" -H 'Content-Type: application/json' -d'
{
  "name": "apm-server-key",
  "role_descriptors": {
    "apm_writer": {
      "indices": [{
        "names": ["apm-*"],
        "privileges": ["create_index", "create_doc"]
      }, {
        "names": [".apm-source-map"],
        "privileges": ["read"]
      }, {
        "names": [".apm-agent-configuration"],
        "privileges": ["read"]
      }],
      "cluster": ["monitor"]
    }
  }
}
')

# use grep and sed to get the encoded api key as we may not have jq or a similar tool on the instance
apiKey=$(echo ${jsonBody} |  grep -Eo '"encoded"[^}]*' | grep -Eo ':.*' | sed -r "s/://" | sed -r 's/"//g')

# cache or use cached api key in order to be able to run repeative integration tests,
# very useful during development, without recreating elasticsearch instance every time.
if [ -z "$apiKey" ]
then
    apiKey=`cat .apm_server_api_key`
else
    echo "$apiKey" > .apm_server_api_key
fi

echo "$apiKey"
