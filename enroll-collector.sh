# Write a otel.yml file
cat <<EOF > otel.yml
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
    instance_uid: "01KCQBWBB5ES54Z8J9J2S4XB9B"
    capabilities:
      reports_effective_config: true
    server:
      http:
        endpoint: http://host.docker.internal:8220/v1/opamp
        tls:
          insecure: true
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
  extensions: [opamp]
EOF

# Run a docker container with the otel.yml file
docker run -it --rm --name otel-collector-fleet-opamp -v $(pwd)/otel.yml:/etc/otelcol/config.yaml otel/opentelemetry-collector-contrib:0.142.0 --config /etc/otelcol/config.yaml