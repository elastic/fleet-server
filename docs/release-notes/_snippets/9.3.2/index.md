## 9.3.2 [fleet-server-release-notes-9.3.2]





### Fixes [fleet-server-9.3.2-fixes]


* Add support for OTEL secrets handling. [#6419](https://github.com/elastic/fleet-server/pull/6419) [#6277](https://github.com/elastic/fleet-server/issues/6277)

  Added functionality to replace secrets in OTEL sections (receivers, exporters, processors, extensions, connectors) of a policy.
  
* Fix checkin endpoint compression support. [#6491](https://github.com/elastic/fleet-server/pull/6491) 

  Adds support for gzip compressed requests to the checkin endpoint.
  
* Fix inaccuracies with openapi spec. [#6517](https://github.com/elastic/fleet-server/pull/6517)

