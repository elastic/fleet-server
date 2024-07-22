output:
  elasticsearch:
    hosts: {{ .Hosts }}
    service_token: {{ .ServiceToken }}

fleet.agent.id: e2e-test-id

inputs:
- type: fleet-server
  server:
    instrumentation:
      enabled: true
      hosts:
        - {{ .APMHost }}
      secret_token: "b!gS3cret"
      environment: test-{{ .TestName }}
      global_lables: testName={{ .TestName }}

logging:
  to_stderr: true


