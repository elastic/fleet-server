## 9.2.7 [fleet-server-release-notes-9.2.7]



### Features and enhancements [fleet-server-9.2.7-features-enhancements]


* Support secrets in agent.download section of policy. [#5837](https://github.com/elastic/fleet-server/pull/5837) 
* Support secrets in fleet section of policy. [#5997](https://github.com/elastic/fleet-server/pull/5997) 
* Accept secret references in policies in either inline or path formats. [#5852](https://github.com/elastic/fleet-server/pull/5852) 

  Elastic Agent policies can contain secret references in one of two formats: inline or path.
  With the inline format, the reference looks like this: `&lt;path&gt;: $co.elastic.secret{&lt;secret ref&gt;}`. 
  With the path format, the reference looks like this: `secrets.&lt;path&gt;.id:&lt;secret ref&gt;`.
  This change ensures that Fleet Server accepts secret references in policies in either format.
  


### Fixes [fleet-server-9.2.7-fixes]


* Add support for OTEL secrets handling. [#6419](https://github.com/elastic/fleet-server/pull/6419) [#6277](https://github.com/elastic/fleet-server/issues/6277)

  Added functionality to replace secrets in OTEL sections (receivers, exporters, processors, extensions, connectors) of a policy.
  
* Fix checkin endpoint compression support. [#6491](https://github.com/elastic/fleet-server/pull/6491) 

  Adds support for gzip compressed requests to the checkin endpoint.
  
* Fix inaccuracies with openapi spec. [#6517](https://github.com/elastic/fleet-server/pull/6517) 

