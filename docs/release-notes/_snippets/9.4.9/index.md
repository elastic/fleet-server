## 9.4.9 [fleet-server-release-notes-9.4.9]

### Fixes [fleet-server-9.4.9-fixes]

* Refresh PGP key when server.pgp.upstream_url is changed. [#8121](https://github.com/elastic/fleet-server/pull/8121) [#7836](https://github.com/elastic/fleet-server/issues/7836)
* Retry enrollment write in sync path to reduce ghost agents. [#7960](https://github.com/elastic/fleet-server/pull/7960) [#7741](https://github.com/elastic/fleet-server/issues/7741)
* Avoid out-of-memory kills when many agents check in right after Fleet Server starts. [#8097](https://github.com/elastic/fleet-server/pull/8097) 
* Fix a race condition in the policy monitor that could stop policy delivery and leave agents in the `Updating` state with the message `Waiting for initial configuration and composable variables`. [#8002](https://github.com/elastic/fleet-server/pull/8002)
