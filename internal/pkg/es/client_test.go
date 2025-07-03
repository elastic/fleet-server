// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/certs"
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
		client, err := NewClient(context.Background(), &config.Config{
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

		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
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
		client, err := NewClient(context.Background(), &config.Config{
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

		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
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
		client, err := NewClient(context.Background(), &config.Config{
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

		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := NewClient(ctx, cfg, false)
	require.NoError(t, err)

	_, err = FetchESVersion(ctx, client)

	if build.FIPSDistribution {
		require.ErrorContains(t, err, "tls: internal error")
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
		w.Write(esPingResponse)
	}))

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	server.TLS = &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.NoClientCert,
	}

	server.StartTLS()

	return server
}
