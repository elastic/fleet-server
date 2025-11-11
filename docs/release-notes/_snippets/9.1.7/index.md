## 9.1.7 [fleet-server-release-notes-9.1.7]





### Fixes [fleet-server-9.1.7-fixes]


* Fix issue that was preventing checkin local_metadata from being updated. [#5824](https://github.com/elastic/fleet-server/pull/5824) 

After an Elastic Agent was marked with audit unenrolled, Fleet Server failed to update the document in
        Elasticsearch when it checked in. This fixes that issue, and now the Fleet Server can update the
        document in Elasticsearch, reflecting the actual status of the Elastic Agent.

  
* Fix issue where malformed components field prevents agent authentication. [#5858](https://github.com/elastic/fleet-server/pull/5858) 

