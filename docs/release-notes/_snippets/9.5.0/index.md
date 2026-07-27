## 9.5.0 [fleet-server-release-notes-9.5.0]



### Features and enhancements [fleet-server-9.5.0-features-enhancements]


* Allow Fleet Server to reload TLS certificates without restarting. [#6838](https://github.com/elastic/fleet-server/pull/6838) [#6433](https://github.com/elastic/fleet-server/issues/6433)
* OpAMP RequestInstanceUid flag always forces enrollment. [#6834](https://github.com/elastic/fleet-server/pull/6834) [#6789](https://github.com/elastic/fleet-server/issues/6789)
* Improve bulker performance. [#7190](https://github.com/elastic/fleet-server/pull/7190) 
* Use go&#39;s FIPS module for fips artifacts. [#7219](https://github.com/elastic/fleet-server/pull/7219) 

  Use go&#39;s FIPS module instead of microsoft/go for creating FIPS artifacts.
  Mechanically it sets GOFIPS140=v1.0.0 at compile time which enables
  FIPS mode but does not force it.
  
* Support HTTP Range in File Delivery. [#7319](https://github.com/elastic/fleet-server/pull/7319) 


### Fixes [fleet-server-9.5.0-fixes]


* Enforce policy-based access control on artifact downloads. [#7009](https://github.com/elastic/fleet-server/pull/7009) 

