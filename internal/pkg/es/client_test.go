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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/certs"
	"github.com/stretchr/testify/require"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
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

func TestShouldRetryTimeoutForCreate(t *testing.T) {
	newReq := func(t *testing.T, ctx context.Context, method, rawURL string) *http.Request {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		require.NoError(t, err)
		return req
	}
	timeoutErr := &net.DNSError{IsTimeout: true}
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name string
		req  *http.Request
		err  error
		want bool
	}{
		{"create timeout", newReq(t, t.Context(), http.MethodPut, "http://es/.fleet-agents/_doc/abc?op_type=create&refresh=wait_for"), timeoutErr, true},
		{"create deadline exceeded", newReq(t, t.Context(), http.MethodPut, "http://es/.fleet-agents/_doc/abc?op_type=create"), context.DeadlineExceeded, true},
		{"create non-timeout error", newReq(t, t.Context(), http.MethodPut, "http://es/.fleet-agents/_doc/abc?op_type=create"), errors.New("boom"), false},
		{"create timeout after caller context done", newReq(t, canceledCtx, http.MethodPut, "http://es/.fleet-agents/_doc/abc?op_type=create"), timeoutErr, false},
		{"index without op_type", newReq(t, t.Context(), http.MethodPut, "http://es/.fleet-agents/_doc/abc"), timeoutErr, false},
		{"bulk", newReq(t, t.Context(), http.MethodPost, "http://es/_bulk?op_type=create"), timeoutErr, false},
		{"search", newReq(t, t.Context(), http.MethodPost, "http://es/.fleet-agents/_search"), timeoutErr, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, shouldRetryTimeoutForCreate(tc.req, tc.err))
		})
	}
}

func TestWithRetryOnTimeoutForCreateComposes(t *testing.T) {
	cfg := elasticsearch.Config{}
	WithRetryOnErrs(syscall.ECONNRESET)(&cfg)
	WithRetryOnTimeoutForCreate()(&cfg)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://es/_bulk", nil)
	require.NoError(t, err)
	require.True(t, cfg.RetryOnError(req, syscall.ECONNRESET), "previous predicate must still apply")
	require.False(t, cfg.RetryOnError(req, context.DeadlineExceeded), "timeouts are only retried for creates")
}

// TestRetryOnTimeoutForCreate drives a real transport timeout: the first create
// hangs past ResponseHeaderTimeout, the retry reaches the server again with the
// same path and body, and a non-create request is not retried.
func TestRetryOnTimeoutForCreate(t *testing.T) {
	const index = ".fleet-agents"
	wantRecorded := "/" + index + "/_doc/abc {\"k\":\"v\"}"
	var calls atomic.Int32
	var mu sync.Mutex
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, r.URL.Path+" "+string(b))
		mu.Unlock()
		if calls.Add(1) == 1 {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
			return
		}
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	newClient := func(t *testing.T) *elasticsearch.Client {
		t.Helper()
		cfg := elasticsearch.Config{
			Addresses:  []string{server.URL},
			Transport:  &http.Transport{ResponseHeaderTimeout: 100 * time.Millisecond},
			MaxRetries: 5,
		}
		WithRetryOnTimeoutForCreate()(&cfg)
		cli, err := elasticsearch.NewClient(cfg)
		require.NoError(t, err)
		return cli
	}

	t.Run("create is retried with same path and body", func(t *testing.T) {
		calls.Store(0)
		bodies = nil
		res, err := esapi.IndexRequest{
			Index:      index,
			DocumentID: "abc",
			Body:       strings.NewReader(`{"k":"v"}`),
			OpType:     opTypeCreate,
		}.Do(t.Context(), newClient(t))
		require.NoError(t, err)
		defer res.Body.Close()
		require.Equal(t, http.StatusConflict, res.StatusCode)
		require.Equal(t, int32(2), calls.Load())
		mu.Lock()
		defer mu.Unlock()
		require.Equal(t, []string{wantRecorded, wantRecorded}, bodies)
	})

	t.Run("search is not retried on timeout", func(t *testing.T) {
		calls.Store(0)
		_, err := esapi.SearchRequest{Index: []string{index}}.Do(t.Context(), newClient(t))
		require.Error(t, err)
		require.Equal(t, int32(1), calls.Load())
	})
}
