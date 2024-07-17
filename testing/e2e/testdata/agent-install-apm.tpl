agent.monitoring:
  traces: true
  apm:
    hosts:
      - http://localhost:8200
    environment: test
    secret_token: "b!gS3cret"
    global_labels:
      testName: {{ .TestName }}
