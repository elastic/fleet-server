// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"testing"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// baseTopologyConfig is a minimal valid collector config with otlp→debug pipeline.
	baseTopologyConfig = `
receivers:
  otlp: {}
exporters:
  debug: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`
	// simpleTopologyConfig is like baseTopologyConfig but omits the exporters block.
	simpleTopologyConfig = `
receivers:
  otlp: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`
)

func makeEffectiveConfig(body string) *protobufs.EffectiveConfig {
	return &protobufs.EffectiveConfig{
		ConfigMap: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"": {Body: []byte(body)},
			},
		},
	}
}

func TestHashEffectiveConfig_NilConfig(t *testing.T) {
	hash, err := HashEffectiveConfig(&protobufs.EffectiveConfig{})
	require.NoError(t, err)
	assert.Empty(t, hash)
}

func TestHashEffectiveConfig_EmptyBody(t *testing.T) {
	hash, err := HashEffectiveConfig(makeEffectiveConfig(""))
	require.NoError(t, err)
	assert.Empty(t, hash)
}

func TestHashEffectiveConfig_Determinism(t *testing.T) {
	// Same topology with different service.telemetry must produce the same hash.
	withTelemetry := `
receivers:
  otlp:
    protocols:
      grpc: {}

exporters:
  debug: {}

service:
  telemetry:
    logs:
      level: debug
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`
	withoutTelemetry := `
receivers:
  otlp:
    protocols:
      grpc: {}

exporters:
  debug: {}

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`
	h1, err := HashEffectiveConfig(makeEffectiveConfig(withTelemetry))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(makeEffectiveConfig(withoutTelemetry))
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "telemetry section must not affect the hash")
}

func TestHashEffectiveConfig_KeyOrderInvariant(t *testing.T) {
	// Key order in the YAML must not affect the hash.
	orderA := baseTopologyConfig
	orderB := `
exporters:
  debug: {}
service:
  pipelines:
    logs:
      exporters: [debug]
      receivers: [otlp]
receivers:
  otlp: {}
`
	h1, err := HashEffectiveConfig(makeEffectiveConfig(orderA))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(makeEffectiveConfig(orderB))
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "key order must not affect the hash")
}

func TestHashEffectiveConfig_TopologyChange(t *testing.T) {
	// Changing a receiver must produce a different hash.
	configA := baseTopologyConfig
	configB := `
receivers:
  prometheus: {}
exporters:
  debug: {}
service:
  pipelines:
    logs:
      receivers: [prometheus]
      exporters: [debug]
`
	h1, err := HashEffectiveConfig(makeEffectiveConfig(configA))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(makeEffectiveConfig(configB))
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "different topology must produce different hash")
}

func TestHashEffectiveConfig_AllowlistEnforcement(t *testing.T) {
	// Adding extensions config (outside allowlist) must not change the hash.
	withoutExtensionsConfig := simpleTopologyConfig
	withExtensionsConfig := `
receivers:
  otlp: {}
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`
	h1, err := HashEffectiveConfig(makeEffectiveConfig(withoutExtensionsConfig))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(makeEffectiveConfig(withExtensionsConfig))
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "extensions config must not affect the hash")
}

func TestHashEffectiveConfig_ServiceExtensionsIncluded(t *testing.T) {
	// service.extensions (the active extension list) IS part of the topology.
	withoutExtensions := simpleTopologyConfig
	withExtensions := `
receivers:
  otlp: {}
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`
	h1, err := HashEffectiveConfig(makeEffectiveConfig(withoutExtensions))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(makeEffectiveConfig(withExtensions))
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "service.extensions must be included in the hash")
}

func TestHashEffectiveConfig_HexEncoded(t *testing.T) {
	hash, err := HashEffectiveConfig(makeEffectiveConfig("receivers:\n  otlp: {}\n"))
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	assert.Len(t, hash, 64, "SHA-256 hex digest must be 64 characters")
	for _, c := range hash {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"hash must be lowercase hex, got %c", c)
	}
}
