## 9.5.0 [fleet-server-release-notes-9.5.0]



### Features and enhancements [fleet-server-9.5.0-features-enhancements]


* Allow Fleet Server to reload TLS certificates without restarting. [#6838](https://github.com/elastic/fleet-server/pull/6838) [#6433](https://github.com/elastic/fleet-server/issues/6433)
* Write policy_base_id field at agent enrollment. [#7422](https://github.com/elastic/fleet-server/pull/7422) 
* OpAMP `RequestInstanceUid` flag always forces enrollment. [#6834](https://github.com/elastic/fleet-server/pull/6834) [#6789](https://github.com/elastic/fleet-server/issues/6789)
* Improve bulker performance. [#7190](https://github.com/elastic/fleet-server/pull/7190) 
* Use go&#39;s FIPS module for fips artifacts. [#7219](https://github.com/elastic/fleet-server/pull/7219) 
* Support HTTP range in file delivery. [#7319](https://github.com/elastic/fleet-server/pull/7319) 


### Fixes [fleet-server-9.5.0-fixes]


* Enforce policy-based access control on artifact downloads. [#7009](https://github.com/elastic/fleet-server/pull/7009) 
* Fix agent enrollment failures caused by 409 version conflicts during `.fleet-agents` primary shard relocation. [#7446](https://github.com/elastic/fleet-server/pull/7446) 

