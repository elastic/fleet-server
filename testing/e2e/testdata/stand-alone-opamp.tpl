output:
  elasticsearch:
    hosts: {{ .Hosts }}
    service_token: {{ .ServiceToken }}

fleet.agent.id: e2e-test-id

inputs:
- type: fleet-server
  server:
    feature_flags:
      enable_opamp: true

logging:
  to_stderr: true

