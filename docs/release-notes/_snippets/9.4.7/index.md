## 9.4.7 [fleet-server-release-notes-9.4.7]



### Features and enhancements [fleet-server-9.4.7-features-enhancements]


* Update Go to 1.26.8. [#7757](https://github.com/elastic/fleet-server/pull/7757) 


### Fixes [fleet-server-9.4.7-fixes]


* Allow replace-enrollment of agents assigned to version-specific policy variants. [#7746](https://github.com/elastic/fleet-server/pull/7746)
* Stamp `upgraded_at` on replace-enrollment when the agent version changes. [#7746](https://github.com/elastic/fleet-server/pull/7746) 

  Agentless agents are upgraded by replacing their container with a new image rather
  than via a Fleet upgrade action, so upgraded_at was never set for them. Kibana&#39;s
  version-specific policy assignment task uses upgraded_at to detect that an agent
  needs to be moved to a new policy variant; without it, the agent remained pinned
  to the variant for its previous minor version after a pod roll, causing it to
  silently receive inputs compiled for the wrong agent version. The replace-enrollment
  path now stamps upgraded_at whenever the incoming agent version differs from the
  version recorded in the existing agent document.
  
* Fix secret keys corruption in policy processing. [#7743](https://github.com/elastic/fleet-server/pull/7743) [#7739](https://github.com/elastic/fleet-server/issues/7739)

