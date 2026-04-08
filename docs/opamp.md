# OpAMP

## Implementation differences from the OpAMP specification

Fleet-server implements a subset of the [OpAMP specification](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md) focused on monitoring. The following describes how our implementation differs from the spec.

### Transport

- **HTTP only.** The spec defines both WebSocket and plain HTTP transports. Fleet-server only supports plain HTTP at `/v1/opamp`. WebSocket connections are not supported.

### Authentication

- **API key required.** The spec suggests standard HTTP auth (Basic/Bearer) as optional. Fleet-server requires an Elastic enrollment API key passed via the `Authorization: ApiKey ...` header. Unauthenticated requests are rejected with HTTP 401.

### Server-to-agent features not implemented

Fleet-server operates in monitoring-only mode. The `ServerToAgent` response only contains `instance_uid`; all other fields are unset.

- **No remote configuration.** The spec defines `ServerToAgent.remote_config` for pushing configuration to agents.
- **No connection settings management.** The spec defines `ServerToAgent.connection_settings` for offering new connection settings, TLS certificates, etc.
- **No package management.** The spec defines `ServerToAgent.packages_available` for offering downloadable packages and updates.
- **No server-initiated commands.** The spec defines `ServerToAgent.command` (e.g., restart).
- **No `ServerToAgent.flags`.** The spec defines `ReportFullState` for requesting full agent state re-delivery.
- **No `ServerToAgent.capabilities`.** The spec says the server MUST report its capabilities bitmask in the first response. Fleet-server does not set this field.
- **No `ServerToAgent.agent_identification`.** The spec allows the server to reassign the agent's `instance_uid`.
- **No custom messages.** The spec defines `custom_capabilities` and `custom_message` for extensible server-to-agent communication.

### Agent-to-server fields ignored

Fleet-server reads `instance_uid`, `agent_description`, `capabilities`, `health`, `effective_config`, and `sequence_num` from `AgentToServer` messages. The following fields are ignored:

- `agent_disconnect` — The spec says this MUST be set in the agent's last message.
- `remote_config_status`
- `package_statuses`
- `flags` (e.g., `RequestInstanceUid`)
- `connection_settings_request`
- `available_components`
- `connection_settings_status`
- `custom_capabilities` / `custom_message`

### Elastic-specific extensions

- **Auto-enrollment.** The spec does not define enrollment. Fleet-server auto-enrolls unknown agents on first message using the enrollment API key's associated policy, creating a document in the `.fleet-agents` index with type `OPAMP`.
- **Health-to-status mapping.** Fleet-server maps `ComponentHealth` to simplified statuses (`online`, `error`, `degraded`). The spec's nested `component_health_map` is not traversed; only the top-level health is used.
- **Sensitive value redaction.** Fleet-server redacts keys containing `password`, `token`, `key`, `secret`, `auth`, `certificate`, or `passphrase` from the effective config before persisting.
- **YAML-to-JSON conversion.** Fleet-server parses the effective config body as YAML and re-serializes it to JSON for storage.

### Capabilities

- **Partial capability decoding.** Fleet-server only decodes 6 of the 16 defined `AgentCapabilities` bits: `ReportsStatus`, `AcceptsRemoteConfig`, `ReportsEffectiveConfig`, `ReportsHealth`, `ReportsAvailableComponents`, `AcceptsRestartCommand`. Other capability bits are silently ignored.

### Throttling

- **HTTP-level rate limiting only.** The spec defines throttling via `ServerErrorResponse` with `UNAVAILABLE` type and `RetryInfo`. Fleet-server uses HTTP-level rate limiting middleware (returning 429) and returns 429 for Elasticsearch auth rate limits, but does not use the protobuf-level `RetryInfo` mechanism. Additionally, fleet-server may silenty drop connections before the TLS handshake completes if the server is overloaded.

---

## Setup

This section describes how to connect a OpenTelemetry Collector instance to Fleet Server over OpAMP.

1. Create a deployment in Elastic Cloud.  Integrations Server is not needed as we will instead be
   using the Fleet Server instance built from this repository so it can "speak" OpAMP to the OpenTelemetry
   Collector.
2. Create an Elasticsearch service account token using Kibana > Dev Tools > Console.
   ```
   POST /_security/service/elastic/fleet-server/credential/token/opamp
   ```
3. The OpAMP endpoint is enabled by default. If you need to disable it, add the following to the `fleet-server` input
   section, as a sibling of the `policy.id` key:
   ```yml
   server:
     feature_flags:
       enable_opamp: false
   ```

4. Build the Fleet Server binary for your platform.
   ```
   mage build:local
   ```
5. Run the Fleet Server binary with the above configuration.
   ```
   ./bin/fleet-server
   ```
6. Create a new policy in Fleet. Copy the enrollment token for that policy.
7. Create OpenTelemetry Collector configuration for connecting to the Fleet Server instance and save it as `otel-opamp.yaml`.
   ```yaml
   receivers:
     otlp:
       protocols:
         grpc:
           endpoint: 0.0.0.0:4317

   exporters:
     debug:
       verbosity: detailed

   extensions:
     opamp:
       server:
         http:
           endpoint: http://localhost:8220/v1/opamp
           tls:
             insecure: true
           headers:
             Authorization: ApiKey ${env:FLEET_ENROLLMENT_TOKEN}
       instance_uid: "019b8d7a-2da8-7657-b52d-492a9de33319"

   service:
     pipelines:
       logs:
         receivers: [otlp]
         exporters: [debug]
         extensions: [opamp]
   ```
7. Download and extract an OpenTelemetry Collector Contrib release for your platform from https://github.com/open-telemetry/opentelemetry-collector-releases/releases
8. Run the OpenTelemetry Collector with the above configuration.
   ```
   API_KEY=<enrollment token> ./otelcol-contrib --config ./otel-opamp.yaml
   ```
