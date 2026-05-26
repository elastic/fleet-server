## 9.4.2 [fleet-server-release-notes-9.4.2]





### Fixes [fleet-server-9.4.2-fixes]


* Fix missing authagent in uploadchunk. [#7007](https://github.com/elastic/fleet-server/pull/7007) 

  Validate that the uploading agent of the chunk has the permissions to write that chunk.
  
* OpAMP redact sensitive values in slice maps. [#6955](https://github.com/elastic/fleet-server/pull/6955) [#415](https://github.com/elastic/elastic-agent-libs/issues/415)
* Fix effective_config not removing deleted pipelines for opamp collectors. [#6988](https://github.com/elastic/fleet-server/pull/6988) [#6877](https://github.com/elastic/fleet-server/issues/6877)

