## 9.0.0 [fleet-server-9.0.0-release-notes]

### Features and enhancements [fleet-server-9.0.0-features-enhancements]

* New setting allowing automatic deletion of unenrolled agents in Fleet settings. [#195544]({{kib-pull}}195544)
* Improves filtering and visibility of Uninstalled and Orphaned agents in Fleet, by differentiating them from Offline agents. [#205815]({{kib-pull}}205815)
* Introduces air-gapped configuration for bundled packages in Fleet. [#202435]({{kib-pull}}202435)
* Updates removed parameters of the Fleet -> Logstash output configurations. [#210115]({{kib-pull}}210115)
* Updates the maximum supported package version in Fleet. [#196675]({{kib-pull}}196675)
* Replaces the use of context.TODO and context.Background in logger function calls for most Fleet Server use cases. [#4168]({{fleet-server-pull}}4168) and [#3087]({{fleet-server-issue}}3087)
* Refactor the Fleet Server API constructor to use functional opts instead of a long list of pointers. [#4169]({{fleet-server-pull}}4169) and [#3823]({{fleet-server-issue}}3823)
* Removes the deprecated policy_throttle configuration setting in favour of the newer policy-limit for Fleet Server. [#4288]({{fleet-server-pull}}4288)
* Removes old bundled.yaml from oas, fixed tags. [#194788]({{kib-pull}}194788)
* Adds the ability for Elastic Agent to enroll using a specific ID. [#4290]({{fleet-server-pull}}4290) and [#4226]({{fleet-server-issue}}4226)

### Fixes [fleet-server-9.0.0-fixes]

* Fixes a validation error that occurs on multi-text input fields in Fleet. [#205768]({{kib-pull}}205768)
* Adds a context timeout to the bulker flush in Fleet Server so it times out if it takes more time than the deadline. [#3986]({{fleet-server-pull}}3986)
* Removes a race condition that may occur when remote Elasticsearch outputs are used in Fleet Server. [#4171]({{fleet-server-pull}}4171)
* Uses the chi/middleware.Throttle package to track in-flight requests and return a 429 response when the limit is reached in Fleet Server. [#4402]({{fleet-server-pull}}4402) and [#4400]({{fleet-server-issue}}4400)