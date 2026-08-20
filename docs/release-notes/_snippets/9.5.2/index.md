## 9.5.2 [fleet-server-release-notes-9.5.2]



### Features and enhancements [fleet-server-9.5.2-features-enhancements]


* Add `graceful_force_unenroll` feature flag to gracefully unenroll agents with invalid API keys. When enabled, a checkin request that arrives with an invalid, expired, or disabled API key triggers a three-step escalation instead of the default HTTP 401 response. [#7593](https://github.com/elastic/fleet-server/pull/7593)
* Update Go to 1.26.6. [#7644](https://github.com/elastic/fleet-server/pull/7644) 


### Fixes [fleet-server-9.5.2-fixes]


* Reject stale policy revisions before secret resolution in the policy monitor. [#7572](https://github.com/elastic/fleet-server/pull/7572) [#7570](https://github.com/elastic/fleet-server/issues/7570)
* Read `cgroup` memory limit for cache sizing when `GOMEMLIMIT` is not set. [#7573](https://github.com/elastic/fleet-server/pull/7573)

