## 9.3.5 [fleet-server-release-notes-9.3.5]





### Fixes [fleet-server-9.3.5-fixes]


* Fix missing authagent in uploadchunk. [#7109](https://github.com/elastic/fleet-server/pull/7109) [#7112](https://github.com/elastic/fleet-server/pull/7112) 

  Validate that the uploading agent of the chunk has the permissions to write that chunk.
  
* Fix effective_config not removing deleted pipelines for opamp collectors. [#7109](https://github.com/elastic/fleet-server/pull/7109) [#7112](https://github.com/elastic/fleet-server/pull/7112) [#6877](https://github.com/elastic/fleet-server/issues/6877)

