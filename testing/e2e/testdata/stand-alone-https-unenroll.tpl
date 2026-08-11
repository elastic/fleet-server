output:
  elasticsearch:
    hosts: {{ .Hosts }}
    service_token: {{ .ServiceToken }}

fleet.agent.id: e2e-test-id

inputs:
- type: fleet-server
  cache:
    ttl_api_key: 2s
    jitter_api_key: 0s
  server:
    ssl:
      enabled: true
      certificate: {{ .CertPath }}
      key: {{ .KeyPath }}
      key_passphrase_path: {{ .PassphrasePath }}
    timeouts:
      checkin_long_poll: 5s
      checkin_jitter: 0s
    feature_flags:
      graceful_unenroll_on_invalid_api_key: true
logging:
  to_stderr: true
