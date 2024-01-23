output:
  elasticsearch:
    hosts: {{ .Hosts }}
    service_token: {{ .ServiceToken }}
    proxy_url: {{ .Proxy }}

fleet.agent.id: e2e-test-id

inputs:
- type: fleet-server

logging:
  to_stderr: true
