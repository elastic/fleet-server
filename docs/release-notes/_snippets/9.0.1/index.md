## 9.0.1 [fleet-server-release-notes-9.0.1]

### Fixes [fleet-server-9.0.1-fixes]

* Fix host parsing in Elasticsearch output diagnostics. [#4765](https://github.com/elastic/fleet-server/pull/4765)
* Redact output in bootstrap config logs. [#4775](https://github.com/elastic/fleet-server/pull/4775)
* Mutex protection for remote bulker config. [#4776](https://github.com/elastic/fleet-server/pull/4776)

  Use existing remote bulker mutex to control access to remote bulker configs.

* Enable dead code elimination. [#4784](https://github.com/elastic/fleet-server/pull/4784)

  Add grpcnotrace build tags and ensure DCE (dead code elimination) is enabled.
  Reduce binary size by 34%
