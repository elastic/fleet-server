## 9.2.0 [fleet-server-release-notes-9.2.0]


### Features and enhancements [fleet-server-9.2.0-features-enhancements]

* Add OTel collector properties to policy schema. [#5169](https://github.com/elastic/fleet-server/pull/5169) [#5241](https://github.com/elastic/fleet-server/issues/5241)

  Add OTel collector properties to the policy schema. This way policies defined in Fleet that include
  this data are forwarded to agents.
  
* Add agent_policy_id and policy_revision_idx to checkin requests. [#5501](https://github.com/elastic/fleet-server/pull/5501) [#6446](https://github.com/elastic/elastic-agent/issues/6446)

  Add the agent_policy_id and policy_revision_idx attributes to checkin
  request bodies so an agent is able to inform fleet-server of its exact
  policy. These details will replace the need for an ack on
  policy_change actions, and will be used to determine when to send a
  policy change when there is a new revision available, or when the
  agent is reassigned to a different policy. Add a server setting under
  feature_flags.ignore_checkin_policy_id that disables this behavour and
  restores the previous approach.
  
* Refactor bulk checkin handler. [#5493](https://github.com/elastic/fleet-server/pull/5493) 

  Refactor the bulk checkin handler to allow for future extensions
* Add credentials to OTel Elasticsearch exporters. [#5469](https://github.com/elastic/fleet-server/pull/5469) 

  When a policy includes OTel configuration with Elasticsearch exporters, it configures their credentials using the credentials in the Elasticsearch output.
* Update Golang version to v1.25.1. [#5562](https://github.com/elastic/fleet-server/pull/5562) 



