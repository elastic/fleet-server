## 9.4.10 [fleet-server-release-notes-9.4.10]





### Fixes [fleet-server-9.4.10-fixes]


* Substitute secrets for pending actions during check-in. [#8152](https://github.com/elastic/fleet-server/pull/8152) 

  Fleet Server now replaces `$co.elastic.secret{id}` references in action data
  for actions returned by the check-in pending-actions path. Previously, only
  actions delivered through the dispatcher were substituted, so agents that
  received an action while offline or between check-ins got the literal secret
  reference instead of the secret value.
  
* Fix doubled route metrics and missing request logs when OpAMP is enabled. [#8276](https://github.com/elastic/fleet-server/pull/8276) 

  When the OpAMP endpoint was enabled, Fleet Server counted each API request two times in the active and total route metrics. Requests that a route limit rejected did not show in the request log or in APM. Fleet Server now counts each request one time and logs and traces rejected requests like other responses.

