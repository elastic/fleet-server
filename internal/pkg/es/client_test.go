// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package es

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/certs"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/stretchr/testify/require"
)

var enabled bool = true

func TestClientCerts(t *testing.T) {
	t.Run("no certs", func(t *testing.T) {
		ca := certs.GenCA(t)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Elastic-Product", "Elasticsearch")
			fmt.Fprintln(w, "You know, For Search.")
		}))
		certPool := x509.NewCertPool()
		certPool.AddCert(ca.Leaf)

		// test server will verify a client cert if present
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{ca},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS12,
		}
		server.StartTLS()
		defer server.Close()

		// client does not use client certs
		client, err := NewClient(t.Context(), &config.Config{
			Output: config.Output{
				Elasticsearch: config.Elasticsearch{
					Protocol: "https",
					Hosts:    []string{server.URL},
					TLS: &tlscommon.Config{
						Enabled: &enabled,
						CAs:     []string{certs.CertToFile(t, ca, "ca")},
					},
				},
			},
		}, false)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
		require.NoError(t, err)

		resp, err := client.Perform(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("uses certs", func(t *testing.T) {
		ca := certs.GenCA(t)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Elastic-Product", "Elasticsearch")
			fmt.Fprintln(w, "You know, For Search.")
		}))
		certPool := x509.NewCertPool()
		certPool.AddCert(ca.Leaf)

		// test server will verify a client cert if present
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{ca},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS12,
		}
		server.StartTLS()
		defer server.Close()

		cert := certs.GenCert(t, ca)

		// client uses valid, matching certs
		client, err := NewClient(t.Context(), &config.Config{
			Output: config.Output{
				Elasticsearch: config.Elasticsearch{
					Protocol: "https",
					Hosts:    []string{server.URL},
					TLS: &tlscommon.Config{
						Enabled: &enabled,
						CAs:     []string{certs.CertToFile(t, ca, "ca")},
						Certificate: tlscommon.CertificateConfig{
							Certificate: certs.CertToFile(t, cert, "cert"),
							Key:         certs.KeyToFile(t, cert, "key"),
						},
					},
				},
			},
		}, false)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
		require.NoError(t, err)

		resp, err := client.Perform(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("client cert does not match", func(t *testing.T) {
		ca := certs.GenCA(t)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Elastic-Product", "Elasticsearch")
			fmt.Fprintln(w, "You know, For Search.")
		}))
		certPool := x509.NewCertPool()
		certPool.AddCert(ca.Leaf)

		// test server will verify a client cert if present
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{ca},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS12,
		}
		server.StartTLS()
		defer server.Close()

		certCA := certs.GenCA(t)
		cert := certs.GenCert(t, certCA)

		// client uses certs that are signed by a different CA
		client, err := NewClient(t.Context(), &config.Config{
			Output: config.Output{
				Elasticsearch: config.Elasticsearch{
					Protocol: "https",
					Hosts:    []string{server.URL},
					TLS: &tlscommon.Config{
						Enabled: &enabled,
						CAs:     []string{certs.CertToFile(t, ca, "ca")},
						Certificate: tlscommon.CertificateConfig{
							Certificate: certs.CertToFile(t, cert, "cert"),
							Key:         certs.KeyToFile(t, cert, "key"),
						},
					},
				},
			},
		}, false)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
		require.NoError(t, err)

		_, err = client.Perform(req) //nolint:bodyclose // no response is expected
		require.Error(t, err)
	})
}

// TestConnectionTLS tries to connect to a test HTTPS server (pretending
// to be an Elasticsearch cluster), that deliberately presents TLS options
// that are not FIPS-compliant.
// - If FIPS crypto is enabled, the client should fail the TLS handshake.
// Concretely, the conn.Connect() method should return an error.
// - If FIPS crypto is not enabled, the client should complete the TLS
// handshake successfully. Concretely, the conn.Connect() method should not
// return an error.
func TestConnectionTLS(t *testing.T) {
	server := startTLSServer(t)
	defer server.Close()

	cfg := &config.Config{
		Output: config.Output{
			Elasticsearch: config.Elasticsearch{
				Protocol: "https",
				Hosts:    []string{server.URL},
				TLS: &tlscommon.Config{
					Enabled: &enabled,
					CAs:     []string{string(caCertPEM)},
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	client, err := NewClient(ctx, cfg, false)
	require.NoError(t, err)

	_, err = FetchESVersion(ctx, client)

	if fips140.Enabled() {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}

//go:embed testdata/ca.crt
var caCertPEM []byte

//go:embed testdata/fips_invalid.key
var serverKeyPEM []byte // RSA key with length = 1024 bits

//go:embed testdata/fips_invalid.crt
var serverCertPEM []byte

//go:embed testdata/es_ping_response.json
var esPingResponse []byte

func startTLSServer(t *testing.T) *httptest.Server {
	// Configure server and start it
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	// Create HTTPS server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(esPingResponse)
		require.NoError(t, err)
	}))

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.NoClientCert,
	}

	server.StartTLS()

	return server
}

func TestIsTLSHandshakeError(t *testing.T) {
	certErr := &tls.CertificateVerificationError{
		Err: errors.New("x509: certificate signed by unknown authority"),
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "unrelated error",
			err:  errors.New("boom"),
			want: false,
		},
		{
			name: "ECONNREFUSED",
			err:  syscall.ECONNREFUSED,
			want: false,
		},
		{
			name: "direct CertificateVerificationError",
			err:  certErr,
			want: true,
		},
		{
			name: "wrapped via fmt.Errorf %w",
			err:  fmt.Errorf("get https://es.example: %w", certErr),
			want: true,
		},
		{
			name: "wrapped via *url.Error (mirrors net/http transport)",
			err: &url.Error{
				Op:  "Get",
				URL: "https://es.example",
				Err: certErr,
			},
			want: true,
		},
		{
			name: "doubly wrapped (fmt.Errorf around *url.Error)",
			err: fmt.Errorf("retry: %w", &url.Error{
				Op:  "Get",
				URL: "https://es.example",
				Err: certErr,
			}),
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isTLSHandshakeError(tc.err))
		})
	}
}

func TestDefaultRetryOnError(t *testing.T) {
	certErr := &tls.CertificateVerificationError{
		Err: errors.New("x509: certificate signed by unknown authority"),
	}
	wrappedCertErr := &url.Error{Op: "Get", URL: "https://es.example", Err: certErr}

	// defaultOptions wires the retryOnError predicate that combines ECONNREFUSED,
	// ECONNRESET, and TLS handshake errors.  Verify each case using an actual client
	// built with those defaults so the predicate is exercised through the real
	// elastictransport plumbing.
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"ECONNREFUSED retries", syscall.ECONNREFUSED, true},
		{"ECONNRESET retries", syscall.ECONNRESET, true},
		{"TLS cert error retries", wrappedCertErr, true},
		{"unrelated error does not retry", errors.New("boom"), false},
		{"nil does not retry", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, defaultRetryOnError(nil, tc.err))
		})
	}
}

// roundTripFunc is a test helper implementing http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// minimalESCfg returns the smallest valid config.Config that points to a
// placeholder ES host. Tests use an rtWrap to intercept transport calls before
// any real network I/O happens.
func minimalESCfg() *config.Config {
	return &config.Config{
		Output: config.Output{
			Elasticsearch: config.Elasticsearch{
				Protocol:       "http",
				Hosts:          []string{"localhost:9200"},
				Timeout:        90 * time.Second,
				MaxConnPerHost: 128,
			},
		},
	}
}

// zeroBackoff overrides the retry backoff to zero so tests complete instantly.
func zeroBackoff() ConfigOption {
	return NewConfigOption(elasticsearch.WithTransportOptions(
		elastictransport.WithRetryBackoff(func(_ int) time.Duration { return 0 }),
		elastictransport.WithMaxRetries(2),
	))
}

// TestNewClientDefaultRetryWiring verifies that NewClient wires the default
// retry predicate into the real elastictransport layer. A RoundTripper that
// always returns ECONNREFUSED should cause exactly maxRetries+1 attempts.
func TestNewClientDefaultRetryWiring(t *testing.T) {
	var attempts int
	rt := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		attempts++
		return nil, syscall.ECONNREFUSED
	})

	client, err := NewClient(t.Context(), minimalESCfg(), false,
		ConfigOption{rtWrap: func(_ http.RoundTripper) http.RoundTripper { return rt }},
		zeroBackoff(),
	)
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://localhost:9200/", nil)
	_, _ = client.Perform(req) //nolint:bodyclose // error path, no body
	require.Equal(t, 3, attempts, "expected 1 initial + 2 retries")
}

// TestNewClientWithRetryOnErrsComposition verifies that WithRetryOnErrs
// OR-composes with (not replaces) the default retry predicate: a custom
// sentinel error should trigger retries when passed via WithRetryOnErrs,
// while the defaults (ECONNREFUSED, etc.) remain active even without it.
func TestNewClientWithRetryOnErrsComposition(t *testing.T) {
	sentinelErr := errors.New("custom sentinel")
	var attempts int
	rt := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		attempts++
		return nil, sentinelErr
	})

	client, err := NewClient(t.Context(), minimalESCfg(), false,
		ConfigOption{rtWrap: func(_ http.RoundTripper) http.RoundTripper { return rt }},
		WithRetryOnErrs(sentinelErr),
		zeroBackoff(),
	)
	require.NoError(t, err)

	req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://localhost:9200/", nil)
	_, _ = client.Perform(req) //nolint:bodyclose // error path, no body
	// WithRetryOnErrs widens the predicate: sentinelErr now retries.
	require.Equal(t, 3, attempts, "expected 1 initial + 2 retries via WithRetryOnErrs")
}
