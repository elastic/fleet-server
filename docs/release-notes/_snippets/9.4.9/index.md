## 9.4.9 [fleet-server-release-notes-9.4.9]





### Fixes [fleet-server-9.4.9-fixes]


* Refresh PGP key when server.pgp.upstream_url is changed. [#8157](https://github.com/elastic/fleet-server/pull/8157) [#8159](https://github.com/elastic/fleet-server/pull/8159) 
* Retry enrollment write in sync path to reduce ghost agents. [#8157](https://github.com/elastic/fleet-server/pull/8157) [#8159](https://github.com/elastic/fleet-server/pull/8159) 

  Transient Elasticsearch errors during agent enrollment could leave ghost agents —
  offline agent records that were never successfully enrolled. Fleet Server now
  retries the enrollment write on these transient errors, reducing the likelihood
  of ghost agents appearing during large-scale enrollment bursts.
  
* Avoid out-of-memory kills when many agents check in right after Fleet Server starts. [#8157](https://github.com/elastic/fleet-server/pull/8157) [#8159](https://github.com/elastic/fleet-server/pull/8159) 

  When an agent checked in for a policy that Fleet Server had not cached yet, the
  check-in loaded every policy from Elasticsearch in its own goroutine. Right after
  a start, many agents checking in at once for different policies each ran a full
  load of every policy at the same time, and the memory used by the decoded policies
  could exceed the memory limit of the container and get Fleet Server OOMKilled.
  
  Fleet Server now loads only the policy the agent needs, and agents that ask for the
  same policy while it is being loaded wait for that one load instead of starting
  their own.
  

