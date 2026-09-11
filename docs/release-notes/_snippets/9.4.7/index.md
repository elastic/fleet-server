## 9.4.7 [fleet-server-release-notes-9.4.7]



### Features and enhancements [fleet-server-9.4.7-features-enhancements]


* Update Go to 1.26.8. [#7757](https://github.com/elastic/fleet-server/pull/7757) 


### Fixes [fleet-server-9.4.7-fixes]


* Allow replace-enrollment of agents assigned to version-specific policy variants. [#7779](https://github.com/elastic/fleet-server/pull/7779) 

  The enroll-with-replace path rejected any agent whose document had been
  reassigned to a version-specific policy variant (e.g. &#34;policy#9.6&#34;) by
  Kibana&#39;s version-specific policy assignment task, because it compared the
  raw stored policy ID against the enrollment key&#39;s policy ID, and enrollment
  API keys are only ever bound to the base policy. Containerized (agentless)
  agents hit this whenever their pod was recreated after such a reassignment:
  every re-enrollment attempt failed with AgentNotReplaceable and the agent
  stayed offline permanently. The check now compares base policy IDs, so a
  version-suffixed assignment no longer blocks replacement while enrolling
  into a genuinely different policy is still rejected.
  
* Stamp upgraded_at on replace-enrollment when the agent version changes. [#7779](https://github.com/elastic/fleet-server/pull/7779) 

  Agentless agents are upgraded by replacing their container with a new image rather
  than via a Fleet upgrade action, so upgraded_at was never set for them. Kibana&#39;s
  version-specific policy assignment task uses upgraded_at to detect that an agent
  needs to be moved to a new policy variant; without it, the agent remained pinned
  to the variant for its previous minor version after a pod roll, causing it to
  silently receive inputs compiled for the wrong agent version. The replace-enrollment
  path now stamps upgraded_at whenever the incoming agent version differs from the
  version recorded in the existing agent document.
  
* Fix secret keys corruption in policy processing. [#7779](https://github.com/elastic/fleet-server/pull/7779) 

