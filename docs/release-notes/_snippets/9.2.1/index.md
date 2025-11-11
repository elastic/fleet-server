## 9.2.1 [fleet-server-release-notes-9.2.1]





### Fixes [fleet-server-9.2.1-fixes]


* Fix issue that was preventing checkin local_metadata from being updated. [#5824](https://github.com/elastic/fleet-server/pull/5824) 

  Once an Elastic Agent is marked with audit unenrolled Fleet Server fails to update the document in
  Elasticsearch when it checks in. This fixes that issue an now the Fleet Server will be able to update the
  document in Elasticsearch reflecting the actual status of the Elastic Agent.
  
* Fix issue where malformed components field prevents agent authentication. [#5858](https://github.com/elastic/fleet-server/pull/5858) 

