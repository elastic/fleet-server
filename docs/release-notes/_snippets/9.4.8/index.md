## 9.4.8 [fleet-server-release-notes-9.4.8]





### Fixes [fleet-server-9.4.8-fixes]


* Fix agent permanently stuck in &#34;updating&#34; state after fast upgrade. [#7799](https://github.com/elastic/fleet-server/pull/7799) 

  Agents that completed an upgrade faster than one checkin interval (~60 s)
  were permanently shown as &#34;updating&#34; in the Fleet UI. Fleet Server now
  detects the completed upgrade and clears the stuck state on the next checkin.
  
* Reject invalid concurrency limits at configuration load time. [#7931](https://github.com/elastic/fleet-server/pull/7931) 

  `bulk.flush_max_pending` and `output.elasticsearch.max_conn_per_host` must now
  be positive. A zero or negative value produced a semaphore that could never be
  acquired, silently wedging the bulker. The `max` setting of the endpoint limits
  that bound concurrent requests (for example `checkin_limit` or `status_limit`)
  must now be zero or positive. Invalid values are reported as a configuration
  error on startup.
  

