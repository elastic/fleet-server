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
          Authorization: ApiKey {{ .OpAMP.APIKey }}
    instance_uid: {{ .OpAMP.InstanceUID }}

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
  extensions: [opamp]