## 9.4.5 [fleet-server-release-notes-9.4.5]



### Features and enhancements [fleet-server-9.4.5-features-enhancements]


* Write the `policy_base_id` field at agent enrollment. [#7422](https://github.com/elastic/fleet-server/pull/7422) 
* Bump `elastic-agent-libs` to v0.46.0 for FIPS 140-3 peer cert key-type enforcement. [#7454](https://github.com/elastic/fleet-server/pull/7454) [#7536](https://github.com/elastic/fleet-server/issues/7536)


### Fixes [fleet-server-9.4.5-fixes]


* Anchor artifact authorization on enrollment-derived policy ID. [#7507](https://github.com/elastic/fleet-server/pull/7507) [#7536](https://github.com/elastic/fleet-server/issues/7536)
* Enforce policy-based access control on artifact downloads. [#7162](https://github.com/elastic/fleet-server/pull/7162) [#7536](https://github.com/elastic/fleet-server/issues/7536)
* Treat output names as parameters in Elasticsearch update scripts. [#7541](https://github.com/elastic/fleet-server/pull/7541) [#7536](https://github.com/elastic/fleet-server/issues/7536)
* Fix agent enrollment failures caused by 409 version conflicts during `.fleet-agents` primary shard relocation. [#7446](https://github.com/elastic/fleet-server/pull/7446) 
* Retain output API key secrets when agent document updates fail. [#7545](https://github.com/elastic/fleet-server/pull/7545) [#7536](https://github.com/elastic/fleet-server/issues/7536)
* Fix spurious `resolveSeqNo` errors on check-in when the `.fleet-actions` index does not exist. [#7548](https://github.com/elastic/fleet-server/pull/7548)

