## 9.4.6 [fleet-server-release-notes-9.4.6]



### Features and enhancements [fleet-server-9.4.6-features-enhancements]


* Add graceful_force_unenroll feature flag to gracefully unenroll agents with invalid API keys. [#7686](https://github.com/elastic/fleet-server/pull/7686) [#7706](https://github.com/elastic/fleet-server/pull/7706) 

  Fleet Server now supports a new `graceful_force_unenroll` block under
  `inputs[].server.feature_flags`. When enabled, a checkin request that arrives
  with an invalid, expired, or disabled API key triggers a three-step escalation
  instead of the default HTTP 401 response:
  
  1. First occurrence: HTTP 200 with a POLICY_CHANGE action carrying an empty policy,
     causing the agent to stop all running inputs.
  2. Second occurrence: HTTP 200 with an UNENROLL action, causing the agent to
     disenroll itself and exit.
  3. Third and subsequent occurrences: HTTP 401 pass-through for up to one hour,
     after which the cycle resets from step 1.
  
  Per-agent escalation state is stored in a memory-bounded LRU (default 50 MB,
  ~200,000 entries). The cap is configurable via `max_bytes` (integer bytes; the
  default 50000000 holds ~200,000 entries). When the LRU is full, the least-recently-used
  entry is evicted, resetting that agent&#39;s escalation back to step 1.
  
  The feature is disabled by default; existing behaviour is unchanged unless
  `enabled: true` is set explicitly.
  
* Update Go to 1.26.6. [#7644](https://github.com/elastic/fleet-server/pull/7644) 
* Prevent ghost agent documents caused by concurrent enrollment retries. [#7686](https://github.com/elastic/fleet-server/pull/7686) [#7706](https://github.com/elastic/fleet-server/pull/7706) 

  At large scale, concurrent enrollment retries could create duplicate (ghost) agent
  documents in Elasticsearch. This occurred when an agent retried enrollment before
  its previous write was visible to search, causing multiple retries to each believe
  no agent existed and each create a new document.
  
  Fleet Server now batches enrollment lookups and ensures index visibility before
  searching, so retries consistently find an existing agent document rather than
  creating a new one. Duplicate requests within a batch are handled efficiently
  and prompted to retry, keeping the number of Elasticsearch operations low.
  
  The batching behaviour is configurable via
  inputs[].server.bulk.enroll.flush_interval (default: 1s) and
  inputs[].server.bulk.enroll.flush_threshold_cnt (default: 50).
  


### Fixes [fleet-server-9.4.6-fixes]


* Reject stale policy revisions before secret resolution in the policy monitor. [#7572](https://github.com/elastic/fleet-server/pull/7572) [#7570](https://github.com/elastic/fleet-server/issues/7570)

  After a Kibana index migration, the `.fleet-policies` change-feed can deliver
  older revision documents (with higher _seq_no values) after the policy monitor
  has already cached a newer revision. Fleet Server now checks the incoming
  revision_idx against the cached revision before attempting to parse the policy
  or resolve its secrets. Stale revisions are dropped with a warning log and do
  not overwrite the cached policy.
  
* Read cgroup memory limit for cache sizing when GOMEMLIMIT is not set. [#7686](https://github.com/elastic/fleet-server/pull/7686) [#7706](https://github.com/elastic/fleet-server/pull/7706) 

  containerMemoryMB() now falls back to the cgroup memory limit (v2 then v1) before host RAM. This ensures fleet-server is correctly sized for the container even in deployments that do not explicitly set GOMEMLIMIT.
  

