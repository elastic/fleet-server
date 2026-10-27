# Feature flags service (proof of concept)

Fleet Server can serve feature flag evaluations to [OpenFeature](https://openfeature.dev) SDKs through the
[OpenFeature Remote Evaluation Protocol (OFREP)](https://github.com/open-feature/protocol).
Flags, apps, environments and credentials are managed in Kibana, which stores them in Elasticsearch.
Fleet Server keeps them in memory, evaluates them, and can report the evaluation contexts it sees so
that Kibana can suggest attributes and values in its rule editor.

The service is experimental and disabled by default.

The code lives in [`internal/pkg/featureflags`](../internal/pkg/featureflags). It only depends on Fleet
Server for its configuration, and talks to Elasticsearch through a small interface
(`esclient.Client`: `Search` and `Bulk`), so it can be extracted into its own service later.

| Package | Role |
|---|---|
| `featureflags` | `Module`: `New(cfg, client, logger)`, `Run(ctx)`, `Handler()`, `Ready()` |
| `featureflags/esclient` | The Elasticsearch interface and its go-elasticsearch implementation |
| `featureflags/definitions` | Documents of the definitions index |
| `featureflags/store` | Immutable in-memory snapshot and the sync loop |
| `featureflags/eval` | Rules engine |
| `featureflags/ofrep` | OFREP HTTP handler (auth, CORS, single and bulk evaluation) |
| `featureflags/observed` | Observed contexts collector |

## Configuration

The section is `inputs[].feature_flags_service`, next to `server`, `cache` and `monitor`. It is not
related to `server.feature_flags`, which holds Fleet Server's own internal toggles. In agent mode, it is
set in the Fleet Server integration's input configuration.

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Enables the OFREP endpoints and the definitions sync. |
| `poll_interval` | `10s` | How often the definitions index is polled for changes. Minimum `1s`. |
| `poll_overlap` | `60s` | Subtracted from the start of the last successful poll, to absorb refresh delay and clock skew. |
| `resync_interval` | `1h` | How often all the definitions are reloaded. Must not be lower than `poll_interval`. |
| `definitions_index` | `.feature-flags-definitions` | Index with environments, apps, credentials and flags. |
| `observed_contexts_index` | `.feature-flags-observed-contexts` | Index the observed contexts are written to. |
| `cors.allowed_origins` | `[]` | Origins allowed to call the endpoints from a browser. `*` allows any origin. |
| `observed_contexts.enabled` | `false` | Records the evaluation contexts. |
| `observed_contexts.flush_interval` | `60s` | How often the contexts are written. Minimum `1s`. |
| `observed_contexts.max_new_contexts_per_flush` | `1000` | Previously unseen contexts written per app and environment on each flush; the rest are dropped. |
| `observed_contexts.last_seen_resolution` | `1h` | A known context is written again only when its `last_seen` moves by more than this. |
| `observed_contexts.exclude_attributes` | `[]` | Context attributes (dotted keys) that are never stored. |

The endpoints are rate limited by `server.limits.ofrep_limit` (by default an interval of `1ms`, a burst
of `1000`, no maximum of concurrent requests, and a `64KiB` body limit). Their metrics are reported under
`http_server.routes.ofrep`.

Changing the section restarts Fleet Server's subsystems, like other server configuration changes.

```yaml
inputs:
  - type: fleet-server
    feature_flags_service:
      enabled: true
      cors:
        allowed_origins: ["https://my-app.example.com"]
      observed_contexts:
        enabled: true
        exclude_attributes: ["user.email"]
```

## Data model

Fleet Server never creates or writes to the definitions index; Kibana creates both indices when its
feature flags plugin is enabled.

`.feature-flags-definitions` holds every entity type, distinguished by a `type` field:
`{ "type": ..., "created_at": ..., "updated_at": ..., "<type>": { ... } }`.

- `environment`: `{ key, name, description }`
- `app`: `{ key, name, description }`
- `credential`: `{ app, environment, sdk_key_hash, sdk_key_hint, client_id }`, one per app and environment.
  `sdk_key_hash` is the hex SHA-256 of the SDK key, which is never stored. `client_id` is public and
  stored in plain text.
- `flag`:

```json
{ "type": "flag", "created_at": "...", "updated_at": "...", "flag": {
  "key": "discover.cascadeLayoutEnabled", "value_type": "boolean", "variations": [true, false],
  "apps": ["kibana"], "tags": [], "created_by": { "username": "alice" },
  "environments": { "qa": { "default": false,
    "prerequisites": [{ "flag": "other.flag", "value": true }],
    "rules": [
      { "type": "match", "attribute": "kibana.offering", "operator": "in", "values": ["serverless"],
        "rules": [{ "type": "percentage", "per_attribute": "organization.key", "percentages": { "true": 10, "false": 90 } }] },
      { "type": "match", "attribute": "kibana.version", "operator": "semver_lt", "values": ["9.3.2"], "return": false } ] } } } }
```

`created_by` is optional metadata that Kibana records when a flag is created. Fleet Server does not
use it when evaluating the flag.

### Evaluation

- Rules are evaluated in order; the first match wins. If none matches, the environment's `default` is served.
- A `match` rule compares a context attribute with `values` using `operator`: `in` (the default),
  `not_in`, `semver_lt`, `semver_gt`, `semver_lte` or `semver_gte`. Values are compared by their string
  form, so `123` matches `"123"`. `not_in` also matches when the attribute is missing. A semver rule
  matches when the comparison holds for any of the values, and never matches an unparsable version.
  List attributes match `in` when any element is in `values`.
- A `match` rule either returns a variation (`return`) or evaluates nested `rules`, which combines the
  conditions with AND. If no nested rule matches, the rule's own `return` is used when set; otherwise
  evaluation continues with the next rule.
- A `percentage` rule hashes `per_attribute` and assigns a variation by cumulative weight, in the order of
  the flag's `variations`. The bucket is `sha256(flagKey + ":" + value) mod 100`. When the attribute is
  missing, the rule does not apply, except for `targetingKey`, which fails with `TARGETING_KEY_MISSING`.
  Percentage rules can be nested in match rules.
- `prerequisites` are evaluated for the same environment and context, before the rules. When a
  prerequisite doesn't evaluate to its `value`, or doesn't exist, the flag is not served (`GENERAL`),
  and the caller uses its own fallback instead of this flag's default variation. The default variation
  is served only when every prerequisite is met and no rule matches. Prerequisite cycles and chains
  deeper than 10 also fail with `GENERAL`.
- An invalid flag (for example, percentages that don't sum to 100) fails with `PARSE_ERROR`.

Context attributes are dotted keys. Both flat keys (`{"kibana.version": "9.3.0"}`) and nested objects
(`{"kibana": {"version": "9.3.0"}}`) are accepted. `targetingKey` is a normal attribute and must be a string.

### Sync

- On start, all documents are loaded from a point in time, paged with `search_after` on `_shard_doc`.
  The endpoints answer `503` until then. A timed-out search, or one with failed shards, is discarded.
- Every `poll_interval`, one search fetches the documents with `updated_at` greater than or equal to the
  start of the last successful poll minus `poll_overlap`. A `global` aggregation in the same request
  counts all the documents of the index. Documents with unchanged `_seq_no` and `_primary_term` are skipped
  while the index UUID is the same. A recreated index, which can reuse those version numbers, is fully reloaded.
  A failed poll keeps the lower bound, so the window widens until a poll succeeds.
- Deletes are detected by comparing the number of documents in memory, after applying the changes, with
  the index count. A difference triggers a full reload. A deleted document is therefore removed on the
  poll after its deletion, not instantly.
- Every `resync_interval`, all documents are reloaded.
- A missing index means no flags (`FLAG_NOT_FOUND`); polling continues quietly.

### Observed contexts

`.feature-flags-observed-contexts` holds one document per app, environment and context, with ID
`sha256(app|environment|context_key)`:

```json
{ "app": "kibana", "environment": "production",
  "context_key": "<targetingKey, or the sha256 of the canonical context when there is none>",
  "context": { "kibana.version": "9.6.0", "organization.key": "123" },
  "attributes": ["kibana.version", "organization.key"],
  "attribute_types": { "kibana.version": "string", "organization.key": "string" },
  "first_seen": "...", "last_seen": "..." }
```

- Collection never blocks requests: contexts are buffered in memory and dropped when the buffers are full.
- `exclude_attributes` are dropped before anything is stored. Values are truncated to 256 characters.
  The document identity uses the original targeting key, before that truncation. Lists are stored as
  their JSON string.
- An update moves `last_seen` forward only. A delayed write from another Fleet Server instance does not
  overwrite a newer observation.
- Every `flush_interval`, contexts are upserted with a single `_bulk` request. New ones are created with
  `first_seen`; known ones only update `context`, `attributes`, `attribute_types` and `last_seen`.
- The flush is skipped when the index doesn't exist, so Fleet Server never creates it.

## OFREP usage

Authenticate with `Authorization: Bearer <token>` (or `X-API-Key: <token>`), where the token is an SDK
key or a client ID. The token determines the app and environment. Use SDK keys on servers and client IDs
in browsers.

```sh
curl -X POST https://fleet-server:8220/ofrep/v1/evaluate/flags/discover.cascadeLayoutEnabled \
  -H "Authorization: Bearer $SDK_KEY" -H "Content-Type: application/json" \
  -d '{"context": {"targetingKey": "org-123", "kibana": {"offering": "serverless", "version": "9.4.0"}}}'
# {"key":"discover.cascadeLayoutEnabled","value":true,"reason":"SPLIT","variant":"true"}
```

- `POST /ofrep/v1/evaluate/flags/{key}` evaluates one flag. A flag that doesn't exist, isn't assigned to
  the caller's app, or has no configuration for its environment returns `404` with `FLAG_NOT_FOUND`.
  Other evaluation errors (`INVALID_CONTEXT`, `PARSE_ERROR`, `TARGETING_KEY_MISSING`, `GENERAL`) return `400`.
- `POST /ofrep/v1/evaluate/flags` evaluates every flag of the caller's app and environment. The response
  has an `ETag` that depends on the definitions, the caller and the context; sending it back in
  `If-None-Match` returns `304` when nothing changed.
- Reasons are `STATIC` (no rules or prerequisites), `TARGETING_MATCH`, `SPLIT` and `DEFAULT`.
- Missing or unknown tokens return `401`. Variants are the string form of the variation values.

## Limitations

- Elasticsearch must allow access to the indices. They are registered as a `.feature-flags*` system
  index, and the `fleet-server` service account needs `read` and `view_index_metadata` on
  `.feature-flags-definitions*` and `read` and `write` on `.feature-flags-observed-contexts*`.
  `view_index_metadata` is what allows reading the index UUID. Without it, definitions still load and a
  recreated index is picked up on the next full resync. Until that change reaches Elasticsearch snapshots,
  run Elasticsearch from source (for example with `yarn es source` in Kibana) on the branch with the grants.
- Observed contexts, including the `targetingKey`, may contain personal data. Collection is opt-in and
  attributes can be excluded; Kibana enforces retention.
- `DEFAULT` is an OpenFeature reason but isn't in the OFREP success enum; providers pass it through.
- Fleet Server's request logger logs non-2xx responses at info level, which includes `304` responses
  to polling clients.
- There are no integration tests yet; they depend on the Elasticsearch grants.
