## 9.4.5 [fleet-server-release-notes-9.4.5]



### Features and enhancements [fleet-server-9.4.5-features-enhancements]


* Write policy_base_id field at agent enrollment. [#7422](https://github.com/elastic/fleet-server/pull/7422) 
* Bump elastic-agent-libs to v0.46.0 for FIPS 140-3 peer cert key-type enforcement. [#7562](https://github.com/elastic/fleet-server/pull/7562) [#7571](https://github.com/elastic/fleet-server/pull/7571) [#7580](https://github.com/elastic/fleet-server/pull/7580) [#7585](https://github.com/elastic/fleet-server/pull/7585) [#7536](https://github.com/elastic/fleet-server/issues/7536)

  Bump elastic-agent-libs to v0.46.0 which enforces FIPS 140-3 compliant peer
  certificate key types across all TLS verification modes. Also set the
  fips140=on GODEBUG default in the FIPS binary so it enforces FIPS mode at
  runtime, and verify this in the binary FIPS marker check.
  


### Fixes [fleet-server-9.4.5-fixes]


* Anchor artifact authorization on enrollment-derived policy ID. [#7562](https://github.com/elastic/fleet-server/pull/7562) [#7571](https://github.com/elastic/fleet-server/pull/7571) [#7580](https://github.com/elastic/fleet-server/pull/7580) [#7585](https://github.com/elastic/fleet-server/pull/7585) [#7536](https://github.com/elastic/fleet-server/issues/7536)
* Enforce policy-based access control on artifact downloads. [#7562](https://github.com/elastic/fleet-server/pull/7562) [#7571](https://github.com/elastic/fleet-server/pull/7571) [#7580](https://github.com/elastic/fleet-server/pull/7580) [#7585](https://github.com/elastic/fleet-server/pull/7585) [#7536](https://github.com/elastic/fleet-server/issues/7536)
* Treat output names as parameters in Elasticsearch update scripts. [#7562](https://github.com/elastic/fleet-server/pull/7562) [#7571](https://github.com/elastic/fleet-server/pull/7571) [#7580](https://github.com/elastic/fleet-server/pull/7580) [#7585](https://github.com/elastic/fleet-server/pull/7585) [#7536](https://github.com/elastic/fleet-server/issues/7536)
* Fix agent enrollment failures caused by 409 version conflicts during `.fleet-agents` primary shard relocation. [#7446](https://github.com/elastic/fleet-server/pull/7446) 
* Retain output API key secrets when agent document updates fail. [#7562](https://github.com/elastic/fleet-server/pull/7562) [#7571](https://github.com/elastic/fleet-server/pull/7571) [#7580](https://github.com/elastic/fleet-server/pull/7580) [#7585](https://github.com/elastic/fleet-server/pull/7585) [#7536](https://github.com/elastic/fleet-server/issues/7536)

  Fleet Server no longer deletes a newly created output API key secret when the
  corresponding agent document update returns an error. Elasticsearch may have
  committed an update even when the client times out waiting for its response;
  deleting the secret in that case leaves the agent with a dangling reference.
  
* Fix spurious resolveSeqNo errors on check-in when .fleet-actions index does not exist. [#7548](https://github.com/elastic/fleet-server/pull/7548) 

