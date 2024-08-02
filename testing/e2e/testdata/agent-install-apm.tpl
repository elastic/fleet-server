agent:
  monitoring:
    traces: true
    apm:
      hosts:
        - {{ .APMHost }}
      environment: test-{{ .TestName }}
      secret_token: "b!gS3cret"
      global_labels:
        testName: {{ .TestName }}
