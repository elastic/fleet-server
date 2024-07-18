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
        "privileges": ["read"],
        "allow_restricted_indices": true
      }, {
        "names": ["traces-apm*", "logs-apm*", "metrics-apm*"],
        "privileges": ["auto_configure", "create_doc"]
      }],
      "cluster": ["monitor"]
    },
    "apm_monitoring_writer": {
      "indices": [{
        "names": [".monitoring-beats-*"],
        "privileges": ["create_index", "create_doc"]
      }]
    },
    "apm_api_key": {
      "cluster": ["manage_own_api_key"],
      "applications": [{
        "application": "apm",
        "privileges": ["event:write"],
        "resources": ["*"]
      }]
    }
  }
}
')

# use grep and sed to get the encoded api key as we may not have jq or a similar tool on the instance
apiKey=$(echo ${jsonBody} |  grep -Eo '"encoded"[^}]*' | grep -Eo ':.*' | sed -r "s/://" | sed -r 's/"//g' | base64 --decode)

# cache ApiKey for testing
if [ -z "$apiKey" ]
then
    apiKey=`cat .apm_server_api_key`
else
    echo "$apiKey" > .apm_server_api_key
fi

echo "$apiKey"
