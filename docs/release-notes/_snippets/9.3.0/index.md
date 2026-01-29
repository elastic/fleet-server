## 9.3.0 [fleet-server-release-notes-9.3.0]



### Features and enhancements [fleet-server-9.3.0-features-enhancements]


* Support secrets in agent.download section of policy. [#6224](https://github.com/elastic/fleet-server/pull/6224) [#6230](https://github.com/elastic/fleet-server/pull/6230) 
* Support secrets in fleet section of policy. [#6224](https://github.com/elastic/fleet-server/pull/6224) [#6230](https://github.com/elastic/fleet-server/pull/6230) 
* Make file storage size configurable. [#6224](https://github.com/elastic/fleet-server/pull/6224) [#6230](https://github.com/elastic/fleet-server/pull/6230) 
* Accept secret references in policies in either inline or path formats. [#6224](https://github.com/elastic/fleet-server/pull/6224) [#6230](https://github.com/elastic/fleet-server/pull/6230) 

  Elastic Agent policies can contain secret references in one of two formats: inline or path.
  With the inline format, the reference looks like this: `&lt;path&gt;: $co.elastic.secret{&lt;secret ref&gt;}`. 
  With the path format, the reference looks like this: `secrets.&lt;path&gt;.id:&lt;secret ref&gt;`.
  This change ensures that Fleet Server accepts secret references in policies in either format.
  
* Improve file upload performance for large files. [#6224](https://github.com/elastic/fleet-server/pull/6224) [#6230](https://github.com/elastic/fleet-server/pull/6230) 


### Fixes [fleet-server-9.3.0-fixes]


* Make action optional when upgrade details are provided. [#6224](https://github.com/elastic/fleet-server/pull/6224) [#6230](https://github.com/elastic/fleet-server/pull/6230) 

