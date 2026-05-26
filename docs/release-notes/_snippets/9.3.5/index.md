## 9.3.5 [fleet-server-release-notes-9.3.5]





### Fixes [fleet-server-9.3.5-fixes]


* Fix missing authagent in uploadchunk. [#7007](https://github.com/elastic/fleet-server/pull/7007) 

  Validate that the uploading agent of the chunk has the permissions to write that chunk.
  
* Fix effective_config not removing deleted pipelines for opamp collectors. [#6988](https://github.com/elastic/fleet-server/pull/6988) [#6877](https://github.com/elastic/fleet-server/issues/6877)

