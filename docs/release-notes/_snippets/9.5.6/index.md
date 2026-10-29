## 9.5.6 [fleet-server-release-notes-9.5.6]


### Fixes [fleet-server-9.5.6-fixes]

* Refresh PGP key when server.pgp.upstream_url is changed. [#7938](https://github.com/elastic/fleet-server/pull/7938) [#7836](https://github.com/elastic/fleet-server/issues/7836)
* Retry enrollment write in sync path to reduce ghost agents. [#7945](https://github.com/elastic/fleet-server/pull/7945) [#7741](https://github.com/elastic/fleet-server/issues/7741)
* Avoid out-of-memory kills when many agents check in right after Fleet Server starts. [#8083](https://github.com/elastic/fleet-server/pull/8083) 
