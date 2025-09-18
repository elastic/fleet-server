## 9.0.7 [fleet-server-release-notes-9.0.7]




### Fixes [fleet-server-9.0.7-fixes]

* Reset trace links on bulk items when returning to pool. [#5317](https://github.com/elastic/fleet-server/pull/5317)
* Restore connection limiter. [#5372](https://github.com/elastic/fleet-server/pull/5372)

  Restore connection level limiter to prevent OOM incidents.
  This limiter is used in addition to the request-level throttle so that once
  our in-flight requests reaches max_connections a 429 is returned, but if the
  total connections the server uses is over max_connections*1.1 the server drops
  the connection before the TLS handshake.

* Build fleet-server as fully static binary to restore OS matrix compatibility. [#5392](https://github.com/elastic/fleet-server/pull/5392) [#5262](https://github.com/elastic/fleet-server/issues/5262)

