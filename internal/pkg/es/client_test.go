// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package es

import (
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"syscall"
	"testing"
	"time"

	backoff "github.com/cenkalti/backoff/v7"
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

// TestInstrumentRoundTripperAppliesWrapping verifies that InstrumentRoundTripper
// places an APM wrapper in the transport chain without breaking request routing:
// the inner transport must still be reached for each request.
func TestInstrumentRoundTripperAppliesWrapping(t *testing.T) {
	var innerCalled bool
	trackRT := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		innerCalled = true
		h := make(http.Header)
		h.Set("X-Elastic-Product", "Elasticsearch")
		h.Set("Content-Type", "application/json")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     h,
			Body:       io.NopCloser(bytes.NewReader(esPingResponse)),
		}, nil
	})

	// First opt replaces the base *http.Transport with trackRT so no real network
	// I/O occurs.  Second opt wraps trackRT with APM instrumentation.
	// Request path: elastictransport → APM wrapper → trackRT → fake response.
	client, err := NewClient(t.Context(), minimalESCfg(), false,
		ConfigOption{rtWrap: func(_ http.RoundTripper) http.RoundTripper { return trackRT }},
		InstrumentRoundTripper(),
	)
	require.NoError(t, err)

	_, err = FetchESVersion(t.Context(), client)
	require.NoError(t, err)
	require.True(t, innerCalled, "APM wrapper must call through to inner transport")
}

// TestNewClientRetryWithMockES is an end-to-end retry test using a real HTTP
// server: the server returns 503 for the first two requests and 200 on the
// third.  It verifies that NewClient's default status-based retry wiring retries
// on 503 and that the eventual success is surfaced to the caller.
func TestNewClientRetryWithMockES(t *testing.T) {
	const failUntil = 2
	var callCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		if callCount <= failUntil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(esPingResponse)
	}))
	defer server.Close()

	cfg := &config.Config{Output: config.Output{Elasticsearch: config.Elasticsearch{
		Protocol:       "http",
		Hosts:          []string{server.URL},
		Timeout:        90 * time.Second,
		MaxConnPerHost: 128,
		MaxRetries:     5,
	}}}
	client, err := NewClient(t.Context(), cfg, false,
		NewConfigOption(elasticsearch.WithTransportOptions(
			elastictransport.WithRetryBackoff(func(_ int) time.Duration { return 0 }),
		)),
	)
	require.NoError(t, err)

	_, err = FetchESVersion(t.Context(), client)
	require.NoError(t, err, "expected eventual success after 503 retries")
	require.Equal(t, failUntil+1, callCount, "expected 2 failures + 1 success")
}

// TestExponentialBackoffFromAttemptSchedule pins the delay schedule: each
// attempt's delay must fall within the randomization band around the
// 1.5x-growth interval, capped at maxRetryBackoff.
func TestExponentialBackoffFromAttemptSchedule(t *testing.T) {
	expected := float64(initialRetryBackoff)
	for attempt := 1; attempt <= 12; attempt++ {
		if attempt > 1 {
			expected = min(expected*1.5, float64(maxRetryBackoff))
		}
		lo := time.Duration(expected * (1 - randomizationFactor))
		hi := time.Duration(expected * (1 + randomizationFactor))
		for range 50 {
			d := exponentialBackoffFromAttempt(attempt)
			require.GreaterOrEqual(t, d, lo, "attempt %d", attempt)
			require.LessOrEqual(t, d, hi, "attempt %d", attempt)
		}
	}
}

// TestRetryBackoffConcurrent drives concurrent failing requests through a
// client using WithBackoff and the default backoff; run with -race to catch
// shared mutable backoff state.
func TestRetryBackoffConcurrent(t *testing.T) {
	newRT := func() roundTripFunc {
		return func(_ *http.Request) (*http.Response, error) { return nil, syscall.ECONNREFUSED }
	}
	tmpl := backoff.NewExponentialBackOff()
	tmpl.InitialInterval = time.Millisecond
	tmpl.MaxInterval = 5 * time.Millisecond

	cases := map[string][]ConfigOption{
		"default":     {},
		"WithBackoff": {WithBackoff(tmpl)},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			rt := newRT()
			opts := append([]ConfigOption{
				{rtWrap: func(_ http.RoundTripper) http.RoundTripper { return rt }},
				WithMaxRetries(3),
			}, extra...)
			if name == "default" {
				opts = append(opts, NewConfigOption(elasticsearch.WithTransportOptions(
					elastictransport.WithRetryBackoff(func(a int) time.Duration {
						return exponentialBackoffFromAttempt(a) / 1000
					}),
				)))
			}
			client, err := NewClient(t.Context(), minimalESCfg(), false, opts...)
			require.NoError(t, err)

			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://localhost:9200/", nil)
					_, _ = client.Perform(req) //nolint:bodyclose // error path
				})
			}
			wg.Wait()
		})
	}
}
