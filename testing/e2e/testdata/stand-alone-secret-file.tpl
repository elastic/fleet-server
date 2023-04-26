output:
  elasticsearch:
    hosts: {{ .Hosts }}
    service_token_path: {{ .ServiceTokenPath }}

fleet.agent.id: e2e-test-id

inputs:
- type: fleet-server
  server:
    ssl:
      enabled: true
      certificate: {{ .CertPath }}
      key: {{ .KeyPath }}
      key_passphrase_path: {{ .PassphrasePath }}

logging:
  to_stderr: true
