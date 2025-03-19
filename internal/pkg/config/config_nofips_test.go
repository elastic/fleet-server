// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration && !requirefips

package config

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

func TestTLSDefaults(t *testing.T) {
	c, err := LoadFile(filepath.Join("testdata", "tls.yml"))
	require.NoError(t, err)
	require.NotNil(t, c.Output.Elasticsearch.TLS)

	common, err := tlscommon.LoadTLSConfig(c.Output.Elasticsearch.TLS)
	require.NoError(t, err)
	cfg := common.ToConfig()
	assert.Equal(t, uint16(tls.VersionTLS11), cfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
}

func TestTLS10(t *testing.T) {
	c, err := LoadFile(filepath.Join("testdata", "tls10.yml"))
	require.NoError(t, err)
	require.NotNil(t, c.Output.Elasticsearch.TLS)

	common, err := tlscommon.LoadTLSConfig(c.Output.Elasticsearch.TLS)
	require.NoError(t, err)
	cfg := common.ToConfig()
	assert.Equal(t, uint16(tls.VersionTLS10), cfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS10), cfg.MaxVersion)
}
