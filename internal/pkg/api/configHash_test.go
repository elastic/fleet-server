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
	baseConfig = `
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
)

func makeEffectiveConfig(body string) *protobufs.EffectiveConfig {
	return makeEffectiveConfigMulti(map[string]string{"": body})
}

func makeEffectiveConfigMulti(files map[string]string) *protobufs.EffectiveConfig {
	cm := make(map[string]*protobufs.AgentConfigFile, len(files))
	for k, v := range files {
		cm[k] = &protobufs.AgentConfigFile{Body: []byte(v)}
	}
	return &protobufs.EffectiveConfig{
		ConfigMap: &protobufs.AgentConfigMap{ConfigMap: cm},
	}
}

func mustParse(t *testing.T, ec *protobufs.EffectiveConfig) map[string]map[string]any {
	t.Helper()
	parsed, err := parseConfigFiles(ec)
	require.NoError(t, err)
	return parsed
}

func TestHashEffectiveConfig_NilConfig(t *testing.T) {
	hash, err := HashEffectiveConfig(mustParse(t, &protobufs.EffectiveConfig{}))
	require.NoError(t, err)
	assert.Empty(t, hash)
}

func TestHashEffectiveConfig_EmptyBody(t *testing.T) {
	hash, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig("")))
	require.NoError(t, err)
	assert.Empty(t, hash)
}

func TestHashEffectiveConfig_KeyOrderInvariant(t *testing.T) {
	// Key order in the YAML must not affect the hash.
	orderA := baseConfig
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
	h1, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(orderA)))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(orderB)))
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "key order must not affect the hash")
}

func TestHashEffectiveConfig_ContentChange(t *testing.T) {
	// Changing a receiver must produce a different hash.
	configA := baseConfig
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
	h1, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(configA)))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(configB)))
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "different config must produce different hash")
}

func TestHashEffectiveConfig_TelemetryAffectsHash(t *testing.T) {
	// service.telemetry is part of the full config and must affect the hash.
	withTelemetry := `
receivers:
  otlp: {}
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
	h1, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(baseConfig)))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(withTelemetry)))
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "service.telemetry must affect the hash")
}

func TestHashEffectiveConfig_ExtensionsAffectHash(t *testing.T) {
	// All config fields, including extensions, must affect the hash.
	withExtensions := `
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
	withoutExtensions := `
receivers:
  otlp: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`
	h1, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(withExtensions)))
	require.NoError(t, err)
	h2, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(withoutExtensions)))
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "extensions config must affect the hash")
}

func TestHashEffectiveConfig_MultiFile(t *testing.T) {
	receivers := `
receivers:
  otlp: {}
`
	pipeline := `
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`
	// Two separate files should hash differently from the same content in one file.
	hSingle, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig(receivers+pipeline)))
	require.NoError(t, err)
	hMulti, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfigMulti(map[string]string{
		"":         receivers,
		"pipeline": pipeline,
	})))
	require.NoError(t, err)
	assert.NotEqual(t, hSingle, hMulti, "single-file and multi-file configs must produce different hashes")

	// Multi-file hash must be deterministic regardless of Go map iteration order.
	hMulti2, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfigMulti(map[string]string{
		"pipeline": pipeline,
		"":         receivers,
	})))
	require.NoError(t, err)
	assert.Equal(t, hMulti, hMulti2, "multi-file hash must be deterministic")
}

func TestHashEffectiveConfig_HexEncoded(t *testing.T) {
	hash, err := HashEffectiveConfig(mustParse(t, makeEffectiveConfig("receivers:\n  otlp: {}\n")))
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	assert.Len(t, hash, 64, "SHA-256 hex digest must be 64 characters")
	for _, c := range hash {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"hash must be lowercase hex, got %c", c)
	}
}
