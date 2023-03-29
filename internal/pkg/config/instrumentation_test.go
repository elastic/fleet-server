// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPMHTTPTransportOptions(t *testing.T) {
	t.Run("single host", func(t *testing.T) {
		i := &Instrumentation{
			APIKey:      "key-val",
			SecretToken: "token-val",
			Hosts:       []string{"localhost:8080"},
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		require.Len(t, cfg.ServerURLs, 1)
		assert.Equal(t, "localhost:8080", cfg.ServerURLs[0].String())
		assert.Equal(t, "key-val", cfg.APIKey)
		assert.Equal(t, "token-val", cfg.SecretToken)
	})

	t.Run("multiple hosts", func(t *testing.T) {
		i := &Instrumentation{
			APIKey:      "key-val",
			SecretToken: "token-val",
			Hosts:       []string{"localhost:8080", "otherhost:8080"},
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		require.Len(t, cfg.ServerURLs, 2)
		assert.Equal(t, "localhost:8080", cfg.ServerURLs[0].String())
		assert.Equal(t, "otherhost:8080", cfg.ServerURLs[1].String())
		assert.Equal(t, "key-val", cfg.APIKey)
		assert.Equal(t, "token-val", cfg.SecretToken)
	})

	t.Run("skip verify", func(t *testing.T) {
		i := &Instrumentation{
			TLS: InstrumentationTLS{
				SkipVerify: true,
			},
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		assert.True(t, cfg.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("custom ca", func(t *testing.T) {
		i := &Instrumentation{
			TLS: InstrumentationTLS{
				ServerCA: filepath.Join("testdata", "ca.crt"),
			},
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		p, err := os.ReadFile(i.TLS.ServerCA)
		require.NoError(t, err)
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM(p)
		require.True(t, ok, "unable to add cert")

		assert.True(t, pool.Equal(cfg.TLSClientConfig.RootCAs), "expected generated root ca pool to have single CA")
	})

	t.Run("custom cert", func(t *testing.T) {
		i := &Instrumentation{
			TLS: InstrumentationTLS{
				ServerCertificate: filepath.Join("testdata", "fleet-server.crt"),
			},
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		assert.True(t, cfg.TLSClientConfig.InsecureSkipVerify)

		t.Log("start test server to verify TLSClientConfig...")
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: cfg.TLSClientConfig,
			},
		}

		cert, err := tls.LoadX509KeyPair(filepath.Join("testdata", "fleet-server.crt"), filepath.Join("testdata", "fleet-server.key"))
		require.NoError(t, err)

		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Hello, world!")
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}} //nolint:gosec // test case
		srv.StartTLS()
		defer srv.Close()

		resp, err := client.Get(srv.URL) //nolint:noctx // just a test
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("api key file", func(t *testing.T) {
		fileName := writeTestFile(t, "test-key")
		i := &Instrumentation{
			APIKeyFile: fileName,
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		assert.Equal(t, "test-key", cfg.APIKey)
	})

	t.Run("api key value preffered over file", func(t *testing.T) {
		fileName := writeTestFile(t, "test-value")
		i := &Instrumentation{
			APIKey:     "test-key",
			APIKeyFile: fileName,
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		assert.Equal(t, "test-key", cfg.APIKey)
	})

	t.Run("secret token file", func(t *testing.T) {
		fileName := writeTestFile(t, "test-token")
		i := &Instrumentation{
			SecretTokenFile: fileName,
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		assert.Equal(t, "test-token", cfg.SecretToken)
	})

	t.Run("secret token value preffered over file", func(t *testing.T) {
		fileName := writeTestFile(t, "test-value")
		i := &Instrumentation{
			SecretToken:     "test-token",
			SecretTokenFile: fileName,
		}
		cfg, err := i.APMHTTPTransportOptions()
		require.NoError(t, err)

		assert.Equal(t, "test-token", cfg.SecretToken)
	})

	t.Run("api key file does not exist", func(t *testing.T) {
		i := &Instrumentation{
			APIKeyFile: "/path/does/not/exist",
		}
		_, err := i.APMHTTPTransportOptions()
		assert.ErrorAs(t, err, &os.ErrNotExist)
	})
}
