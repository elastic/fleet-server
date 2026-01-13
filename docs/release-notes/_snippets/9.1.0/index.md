## 9.1.0 [fleet-server-release-notes-9.1.0]


### Features and enhancements [fleet-server-9.1.0-features-enhancements]

* Add ability for enrollment to take an agent ID. [#4290](https://github.com/elastic/fleet-server/pull/4290) [#4226](https://github.com/elastic/fleet-server/issues/4226)
* Clear `agent.upgrade_attempts` when upgrade is complete. [#4528](https://github.com/elastic/fleet-server/pull/4528)

  The new AutomaticAgentUpgradeTask Kibana task sets the upgrade_attempts property in agents it upgrades.
  This property is used to track upgrade retries and should therefore be cleared when the upgrade is complete.
* Make pbkdf2 settings validation FIPS compliant. [#4542](https://github.com/elastic/fleet-server/pull/4542)
* Update Go to v1.24.3. [#4891](https://github.com/elastic/fleet-server/pull/4891)
* Add version metadata to version command output. [#4820](https://github.com/elastic/fleet-server/pull/4820)

  Add commit, buildtime, and FIPS distribution indicators to output of version command.
  Add fips-distribution attribute to initial startup log.
* Add rollback attribute to upgrade actions in preparation for enabling upgrade rollbacks in a future release. [#4838](https://github.com/elastic/fleet-server/issues/4838)

### Fixes [fleet-server-9.1.0-fixes]

* Upgrade golang.org/x/net to v0.34.0 and golang.org/x/crypto to v0.32.0. [#4405](https://github.com/elastic/fleet-server/pull/4405)
* Fix host parsing in Elasticsearch output diagnostics. [#4765](https://github.com/elastic/fleet-server/pull/4765)
* Redact output in bootstrap config logs. [#4775](https://github.com/elastic/fleet-server/pull/4775)
* Mutex protection for remote bulker config. [#4776](https://github.com/elastic/fleet-server/pull/4776)

  Use existing remote bulker mutex to control access to remote bulker configs.
* Enable dead code elimination. [#4784](https://github.com/elastic/fleet-server/pull/4784)

  Add grpcnotrace build tags and ensure DCE (dead code elimination) is enabled.
  Reduce binary size by 34%
* Include the base error for json decode error responses. [#5069](https://github.com/elastic/fleet-server/pull/5069)
