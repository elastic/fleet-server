output:
  elasticsearch:
    hosts: {{ .Hosts }}
    service_token: {{ .ServiceToken }}

fleet.agent.id: e2e-test-id

inputs:
- type: fleet-server
  server:
    static_policy_tokens:
      enabled: true
      policy_tokens:
        - token_key: {{ .StaticTokenKey }}
          policy_id: dummy-policy

logging:
  to_stderr: true

