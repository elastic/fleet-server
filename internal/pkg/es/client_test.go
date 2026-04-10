// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/certs"
	"github.com/stretchr/testify/require"

	"github.com/elastic/go-elasticsearch/v8"
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
// - If the test is running with a FIPS-capable build, the client, being FIPS-
// capable, should fail the TLS handshake. Concretely, the conn.Connect() method
// should return an error.
// - If the test is not running with a FIPS-capable build, the client should
// complete the TLS handshake successfully. Concretely, the conn.Connect() method
// should not return an error.
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

	if fips140.Enforced() {
		// When FIPS 140 is enforced (GODEBUG=fips140=only), Go's crypto
		// stack rejects signing with a 1024-bit RSA key. Note: fips140=on
		// with microsoft/go's systemcrypto backend silently falls back to
		// stdlib in test binaries (via UnreachableExceptTests), so only
		// fips140=only reliably enforces this.
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

func TestWithRetryOnTLSHandshakeError(t *testing.T) {
	certErr := &tls.CertificateVerificationError{
		Err: errors.New("x509: certificate signed by unknown authority"),
	}
	wrappedCertErr := &url.Error{Op: "Get", URL: "https://es.example", Err: certErr}

	t.Run("composes with no prior predicate", func(t *testing.T) {
		var cfg elasticsearch.Config
		WithRetryOnTLSHandshakeError()(&cfg)

		require.NotNil(t, cfg.RetryOnError)
		require.True(t, cfg.RetryOnError(nil, wrappedCertErr), "should retry on TLS cert error")
		require.False(t, cfg.RetryOnError(nil, errors.New("other")), "should not retry on unrelated error")
		require.False(t, cfg.RetryOnError(nil, nil), "should not retry on nil error")
	})

	t.Run("composes with prior predicate (OR semantics)", func(t *testing.T) {
		var cfg elasticsearch.Config
		// Prior predicate retries only on ECONNREFUSED.
		WithRetryOnErrs(syscall.ECONNREFUSED)(&cfg)
		WithRetryOnTLSHandshakeError()(&cfg)

		require.NotNil(t, cfg.RetryOnError)
		// Prior predicate still honored.
		require.True(t, cfg.RetryOnError(nil, syscall.ECONNREFUSED))
		// New TLS predicate triggers.
		require.True(t, cfg.RetryOnError(nil, wrappedCertErr))
		// Neither matches.
		require.False(t, cfg.RetryOnError(nil, syscall.ECONNRESET))
	})
}
