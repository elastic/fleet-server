## 9.3.4 [fleet-server-release-notes-9.3.4]



### Features and enhancements [fleet-server-9.3.4-features-enhancements]


* Update go to v1.26.2. [#6800](https://github.com/elastic/fleet-server/pull/6800) 


### Fixes [fleet-server-9.3.4-fixes]


* Retry Elasticsearch requests on TLS handshake errors so multi-host outputs can fail over. [#6767](https://github.com/elastic/fleet-server/pull/6767) 
* Fix typos in default rate limit YAML keys that prevented PGP retrieval and policy limits from loading. [#6835](https://github.com/elastic/fleet-server/pull/6835) 

