## 9.4.2 [fleet-server-release-notes-9.4.2]





### Fixes [fleet-server-9.4.2-fixes]


* Fix missing authagent in uploadchunk. [#7108](https://github.com/elastic/fleet-server/pull/7108) [#7113](https://github.com/elastic/fleet-server/pull/7113) 

  Validate that the uploading agent of the chunk has the permissions to write that chunk.
  
* OpAMP redact sensitive values in slice maps. [#7108](https://github.com/elastic/fleet-server/pull/7108) [#7113](https://github.com/elastic/fleet-server/pull/7113) [#415](https://github.com/elastic/elastic-agent-libs/issues/415)
* Fix effective_config not removing deleted pipelines for opamp collectors. [#7108](https://github.com/elastic/fleet-server/pull/7108) [#7113](https://github.com/elastic/fleet-server/pull/7113) [#6877](https://github.com/elastic/fleet-server/issues/6877)

