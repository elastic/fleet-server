## 9.4.0 [fleet-server-release-notes-9.4.0]



### Features and enhancements [fleet-server-9.4.0-features-enhancements]


* Adds file-delivery source routing to integration indices. [#6599](https://github.com/elastic/fleet-server/pull/6599) 

  Adds an optional query parameter (?source) to the existing file delivery API. When
  omitted, files are pulled from the fleet-owned file data streams as before. When used,
  fleet server will pull from the calling integration&#39;s owned indices.
  
* Update go to v1.26.2. [#6800](https://github.com/elastic/fleet-server/pull/6800) 


### Fixes [fleet-server-9.4.0-fixes]


* Retry Elasticsearch requests on TLS handshake errors so multi-host outputs can fail over. [#6767](https://github.com/elastic/fleet-server/pull/6767) 
* Handle OpAMP AgentDisconnect message by setting agent status to disconnected. [#6792](https://github.com/elastic/fleet-server/pull/6792) [#6784](https://github.com/elastic/fleet-server/issues/6784)
* Report server capabilities in OpAMP ServerToAgent responses as required by the spec. [#6829](https://github.com/elastic/fleet-server/pull/6829) [#6785](https://github.com/elastic/fleet-server/issues/6785)
* Decode all opamp-agent capabilites. [#6830](https://github.com/elastic/fleet-server/pull/6830) [#6790](https://github.com/elastic/fleet-server/issues/6790)
* Always Set ReportFullState flag in OpAMP responses. [#6831](https://github.com/elastic/fleet-server/pull/6831) [#6783](https://github.com/elastic/fleet-server/issues/6783)
* Fix typos in default rate limit YAML keys that prevented PGP retrieval and policy limits from loading. [#6835](https://github.com/elastic/fleet-server/pull/6835) 

