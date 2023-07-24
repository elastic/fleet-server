output:
  elasticsearch:
    hosts: {{ .Hosts }}
    service_token: {{ .ServiceToken }}

fleet.agent.id: e2e-test-id

inputs:
- type: fleet-server
  server:
    ssl:
      enabled: true
      certificate: {{ .CertPath }}
      key: {{ .KeyPath }}
      key_passphrase_path: {{ .PassphrasePath }}
  {{ if .StaticPolicyTokenEnabled }}
    static_policy_tokens:
      enabled: {{ .StaticPolicyTokenEnabled }}
      policy_tokens:
        - token_key: {{ .StaticTokenKey }}
          policy_id: {{ .StaticPolicyID }}
  {{ end }}
logging:
  to_stderr: true
