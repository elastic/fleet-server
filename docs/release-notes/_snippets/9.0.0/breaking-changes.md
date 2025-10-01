## 9.0.0 [fleet-server-9.0.0-breaking-changes]

::::{dropdown} Removed deprecated epm Fleet APIs
Removed `GET/POST/DELETE /epm/packages/:pkgkey` APIs in favor of the `GET/POST/DELETE /epm/packages/:pkgName/:pkgVersion`.

**Impact**<br>
* Removed `experimental` query parameter in `GET /epm/packages` and `GET /epm/categories`
* Removed `response` in response in `* /epm/packages*` and `GET /epm/categories`
* Removed `savedObject` in `/epm/packages` response in favor of `installationInfo`

For more information, check [#198434]({{kib-pull}}198434).
::::

::::{dropdown} Removed deprecated Fleet APIs for agents endpoints
Removed the following API endpoints:

* `POST /service-tokens` in favor of `POST /service_tokens`
* `GET /agent-status` in favor `GET /agent_status`
* `PUT /agents/:agentid/reassign` in favor of `POST /agents/:agentid/reassign`

Removed deprecated parameters or responses:

* Removed `total` from `GET /agent_status` response
* Removed `list` from `GET /agents` response

For more information, check [#198313]({{kib-pull}}198313).
::::

::::{dropdown} Removed deprecated settings API endpoints in Fleet
* `GET/DELETE/POST enrollment-api-keys`: removed in favor of `GET/DELETE/POST enrollment_api_keys`
* Removed `list` property from `GET enrollment_api_keys` response in favor of `items`
* `GET/POST /settings`: `fleet_server_hosts` was removed from the response and body

For more information, check [#198799]({{kib-pull}}198799).
::::

::::{dropdown} Removed deprecated settings API endpoints in Fleet
* `GET/DELETE/POST enrollment-api-keys`: removed in favor of `GET/DELETE/POST enrollment_api_keys`
* Removed `list` property from `GET enrollment_api_keys` response in favor of `items`
* `GET/POST /settings`: `fleet_server_hosts` was removed from the response and body

For more information, check [#198799]({{kib-pull}}198799).
::::

::::{dropdown} Removed deprecated topics property for kafka output in favor of the topic property
Removed deprecated property `topics` from output APIs in response and requests (`(GET|POST|PUT) /api/fleet/outputs`) in favor of the `topic` property.

For more information, check [#199226]({{kib-pull}}199226).
::::

::::{dropdown} Limit pagination size to 100 when retrieving full policy or withAgentCount in Fleet
In addition to the new pagination limit size of 100, retrieving agent policies without agent count is now the new default behavior, and a new query parameter `withAgentCount` was added to retrieve the agent count.

For more information, check [#196887]({{kib-pull}}196887).
::::
