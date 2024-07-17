output:
  elasticsearch:
    hosts: {{ .Hosts }}
    service_token: {{ .ServiceToken }}

fleet.agent.id: e2e-test-id

inputs:
- type: fleet-server
  instrumentation:
    enabled: true
    hosts:
      - http://localhost:8200
    secret_token: "b!gs3cret"
    environment: test
    global_lables: testName={{ .TestName }}

logging:
  to_stderr: true


