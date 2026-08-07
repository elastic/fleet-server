## 9.5.1 [fleet-server-release-notes-9.5.1]





### Fixes [fleet-server-9.5.1-fixes]


* Anchor artifact authorization on enrollment-derived policy ID. [#7563](https://github.com/elastic/fleet-server/pull/7563) [#7571](https://github.com/elastic/fleet-server/pull/7571) [#7583](https://github.com/elastic/fleet-server/pull/7583) [#7572](https://github.com/elastic/fleet-server/pull/7572) [#7536](https://github.com/elastic/fleet-server/issues/7536) [#7570](https://github.com/elastic/fleet-server/issues/7570)
* Treat output names as parameters in Elasticsearch update scripts. [#7563](https://github.com/elastic/fleet-server/pull/7563) [#7571](https://github.com/elastic/fleet-server/pull/7571) [#7583](https://github.com/elastic/fleet-server/pull/7583) [#7572](https://github.com/elastic/fleet-server/pull/7572) [#7536](https://github.com/elastic/fleet-server/issues/7536) [#7570](https://github.com/elastic/fleet-server/issues/7570)
* Retain output API key secrets when agent document updates fail. [#7563](https://github.com/elastic/fleet-server/pull/7563) [#7571](https://github.com/elastic/fleet-server/pull/7571) [#7583](https://github.com/elastic/fleet-server/pull/7583) [#7572](https://github.com/elastic/fleet-server/pull/7572) [#7536](https://github.com/elastic/fleet-server/issues/7536) [#7570](https://github.com/elastic/fleet-server/issues/7570)

  Fleet Server no longer deletes a newly created output API key secret when the
  corresponding agent document update returns an error. Elasticsearch may have
  committed an update even when the client times out waiting for its response;
  deleting the secret in that case leaves the agent with a dangling reference.
  
* Fix spurious resolveSeqNo errors on check-in when .fleet-actions index does not exist. [#7548](https://github.com/elastic/fleet-server/pull/7548) 

