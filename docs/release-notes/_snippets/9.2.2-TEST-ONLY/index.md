## 9.2.2-TEST-ONLY [fleet-server-release-notes-9.2.2-TEST-ONLY]



### Features and enhancements [fleet-server-9.2.2-TEST-ONLY-features-enhancements]


* Accept secret references in policies in either inline or path formats. [#5832](https://github.com/elastic/fleet-server/pull/5832) 

  Elastic Agent policies can contain secret references in one of two formats: inline or path.
  With the inline format, the reference looks like this: `&lt;path&gt;: $co.elastic.secret{&lt;secret ref&gt;}`. 
  With the path format, the reference looks like this: `secrets.&lt;path&gt;.id:&lt;secret ref&gt;`.
  This change ensures that Fleet Server accepts secret references in policies in either format.
  



