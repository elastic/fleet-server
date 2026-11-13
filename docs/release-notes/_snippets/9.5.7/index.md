## 9.5.7 [fleet-server-release-notes-9.5.7]





### Fixes [fleet-server-9.5.7-fixes]


* Substitute secrets for pending actions during check-in. [#8192](https://github.com/elastic/fleet-server/pull/8192) [#8225](https://github.com/elastic/fleet-server/pull/8225) [#8237](https://github.com/elastic/fleet-server/pull/8237) 

  Fleet Server now replaces `$co.elastic.secret{id}` references in action data
  for actions returned by the check-in pending-actions path. Previously, only
  actions delivered through the dispatcher were substituted, so agents that
  received an action while offline or between check-ins got the literal secret
  reference instead of the secret value.
  

