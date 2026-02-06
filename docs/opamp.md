# OpAMP

This section describes how to connect a OpenTelemetry Collector instance to Fleet Server over OpAMP.

1. Create a deployment in Elastic Cloud.  Integrations Server is not needed as we will instead be
   using the Fleet Server instance built from this repository so it can "speak" OpAMP to the OpenTelemetry
   Collector.
2. Create an Elasticsearch service account token using Kibana > Dev Tools > Console.
   ```
   POST /_security/service/elastic/fleet-server/credential/token/opamp
   ```
3. Create a `fleet-server.dev.yml` configuration file as described in https://github.com/elastic/kibana/blob/main/x-pack/platform/plugins/shared/fleet/dev_docs/local_setup/developing_kibana_and_fleet_server.md.
4. Build the Fleet Server binary for your platform.
   ```
   PLATFORMS=darwin/arm64 mage build:binary
   ```
5. Run the Fleet Server binary with the above configuration.
   ```
   ./build/binaries/fleet-server-9.4.0-darwin-aarch64/fleet-server -c fleet-server.dev.yml
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
   FLEET_ENROLLMENT_TOKEN=<enrollment token> ./otelcol-contrib --config ./otel-opamp.yaml
   ```
