// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

//nolint:dupl // duplicated lines used for test cases
package config

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/go-elasticsearch/v8"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

func TestToESConfig(t *testing.T) {
	testcases := map[string]struct {
		cfg    Elasticsearch
		result elasticsearch.Config
	}{
		"http": {
			cfg: Elasticsearch{
				Protocol:       "http",
				Hosts:          []string{"localhost:9200"},
				ServiceToken:   "test-token",
				MaxRetries:     3,
				MaxConnPerHost: 128,
				Timeout:        90 * time.Second,
			},
			result: elasticsearch.Config{
				Addresses:    []string{"http://localhost:9200"},
				ServiceToken: "test-token",
				Header:       http.Header{},
				MaxRetries:   3,
				Transport: &http.Transport{
					TLSHandshakeTimeout:   10 * time.Second,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   32,
					MaxConnsPerHost:       128,
					IdleConnTimeout:       60 * time.Second,
					ResponseHeaderTimeout: 90 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			},
		},
		"service_token and service_token_path defined": {
			cfg: Elasticsearch{
				Protocol:         "http",
				Hosts:            []string{"localhost:9200"},
				ServiceToken:     "test-token",
				ServiceTokenPath: "/path/is/ignored",
				MaxRetries:       3,
				MaxConnPerHost:   128,
				Timeout:          90 * time.Second,
			},
			result: elasticsearch.Config{
				Addresses:    []string{"http://localhost:9200"},
				ServiceToken: "test-token",
				Header:       http.Header{},
				MaxRetries:   3,
				Transport: &http.Transport{
					TLSHandshakeTimeout:   10 * time.Second,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   32,
					MaxConnsPerHost:       128,
					IdleConnTimeout:       60 * time.Second,
					ResponseHeaderTimeout: 90 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			},
		},
		"multi-http": {
			cfg: Elasticsearch{
				Protocol:     "http",
				Hosts:        []string{"localhost:9200", "other-host:9200"},
				ServiceToken: "test-token",
				Headers: map[string]string{
					"X-Custom-Header": "Header-Value",
				},
				MaxRetries:     6,
				MaxConnPerHost: 256,
				Timeout:        120 * time.Second,
			},
			result: elasticsearch.Config{
				Addresses:    []string{"http://localhost:9200", "http://other-host:9200"},
				ServiceToken: "test-token",
				Header:       http.Header{"X-Custom-Header": {"Header-Value"}},
				MaxRetries:   6,
				Transport: &http.Transport{
					TLSHandshakeTimeout:   10 * time.Second,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   32,
					MaxConnsPerHost:       256,
					IdleConnTimeout:       60 * time.Second,
					ResponseHeaderTimeout: 120 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			},
		},
		"https": {
			cfg: Elasticsearch{
				Protocol:     "https",
				Hosts:        []string{"localhost:9200", "other-host:9200"},
				ServiceToken: "test-token",
				Headers: map[string]string{
					"X-Custom-Header": "Header-Value",
				},
				MaxRetries:     6,
				MaxConnPerHost: 256,
				Timeout:        120 * time.Second,
				TLS: &tlscommon.Config{
					VerificationMode: tlscommon.VerifyNone,
				},
			},
			result: elasticsearch.Config{
				Addresses:    []string{"https://localhost:9200", "https://other-host:9200"},
				ServiceToken: "test-token",
				Header:       http.Header{"X-Custom-Header": {"Header-Value"}},
				MaxRetries:   6,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, //nolint:gosec // test case
						MinVersion:         tls.VersionTLS11,
						MaxVersion:         tls.VersionTLS13,
						Certificates:       []tls.Certificate{},
						CurvePreferences:   []tls.CurveID{},
					},
					TLSHandshakeTimeout:   10 * time.Second,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   32,
					MaxConnsPerHost:       256,
					IdleConnTimeout:       60 * time.Second,
					ResponseHeaderTimeout: 120 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			},
		},
		"mixed-https": {
			cfg: Elasticsearch{
				Protocol:     "http",
				Hosts:        []string{"localhost:9200", "https://other-host:9200"},
				ServiceToken: "test-token",
				Headers: map[string]string{
					"X-Custom-Header": "Header-Value",
				},
				MaxRetries:     6,
				MaxConnPerHost: 256,
				Timeout:        120 * time.Second,
				TLS: &tlscommon.Config{
					VerificationMode: tlscommon.VerifyNone,
				},
			},
			result: elasticsearch.Config{
				Addresses:    []string{"http://localhost:9200", "https://other-host:9200"},
				ServiceToken: "test-token",
				Header:       http.Header{"X-Custom-Header": {"Header-Value"}},
				MaxRetries:   6,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, //nolint:gosec // test case
						MinVersion:         tls.VersionTLS11,
						MaxVersion:         tls.VersionTLS13,
						Certificates:       []tls.Certificate{},
						CurvePreferences:   []tls.CurveID{},
					},
					TLSHandshakeTimeout:   10 * time.Second,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   32,
					MaxConnsPerHost:       256,
					IdleConnTimeout:       60 * time.Second,
					ResponseHeaderTimeout: 120 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			},
		},
	}

	copts := cmp.Options{
		cmpopts.IgnoreUnexported(http.Transport{}),
		cmpopts.IgnoreFields(http.Transport{}, "DialContext"),
		cmpopts.IgnoreUnexported(tls.Config{}), //nolint:gosec //test case
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			_ = testlog.SetLogger(t)
			res, err := test.cfg.ToESConfig(false)
			require.NoError(t, err)

			// cmp.Diff can't handle function pointers.
			res.Transport.(*http.Transport).Proxy = nil

			test.result.Header.Set("X-elastic-product-origin", "fleet")
			assert.True(t, cmp.Equal(test.result, res, copts...), "mismatch (-want +got)\n%s", cmp.Diff(test.result, res, copts...))
		})
	}

	t.Run("service_token_path is ok", func(t *testing.T) {
		fileName := writeTestFile(t, "test-token")
		cfg := &Elasticsearch{
			Protocol:         schemeHTTP,
			Hosts:            []string{"localhost:9200"},
			ServiceTokenPath: fileName,
			MaxRetries:       3,
			MaxConnPerHost:   128,
			Timeout:          90 * time.Second,
		}
		es, err := cfg.ToESConfig(false)
		require.NoError(t, err)

		expect := elasticsearch.Config{
			Addresses:    []string{"http://localhost:9200"},
			ServiceToken: "test-token",
			Header:       http.Header{"X-Elastic-Product-Origin": []string{"fleet"}},
			MaxRetries:   3,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   10 * time.Second,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   32,
				MaxConnsPerHost:       128,
				IdleConnTimeout:       60 * time.Second,
				ResponseHeaderTimeout: 90 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}

		es.Transport.(*http.Transport).Proxy = nil
		assert.True(t, cmp.Equal(expect, es, copts...), "mismatch (-want +got)\n%s", cmp.Diff(expect, es, copts...))
	})

	t.Run("service_token_path is empty", func(t *testing.T) {
		fileName := writeTestFile(t, "")
		cfg := &Elasticsearch{
			Protocol:         schemeHTTP,
			Hosts:            []string{"localhost:9200"},
			ServiceTokenPath: fileName,
			MaxRetries:       3,
			MaxConnPerHost:   128,
			Timeout:          90 * time.Second,
		}
		es, err := cfg.ToESConfig(false)
		require.NoError(t, err)

		expect := elasticsearch.Config{
			Addresses:  []string{"http://localhost:9200"},
			Header:     http.Header{"X-Elastic-Product-Origin": []string{"fleet"}},
			MaxRetries: 3,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   10 * time.Second,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   32,
				MaxConnsPerHost:       128,
				IdleConnTimeout:       60 * time.Second,
				ResponseHeaderTimeout: 90 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}

		es.Transport.(*http.Transport).Proxy = nil
		assert.True(t, cmp.Equal(expect, es, copts...), "mismatch (-want +got)\n%s", cmp.Diff(expect, es, copts...))
	})

	t.Run("service_token_path does not exist", func(t *testing.T) {
		cfg := &Elasticsearch{
			Protocol:         schemeHTTP,
			Hosts:            []string{"localhost:9200"},
			ServiceTokenPath: filepath.Join(t.TempDir(), "some-file"),
			MaxRetries:       3,
			MaxConnPerHost:   128,
			Timeout:          90 * time.Second,
		}
		_, err := cfg.ToESConfig(false)
		assert.ErrorAs(t, err, &os.ErrNotExist)
	})
}

func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	return f.Name()
}

func TestESProxyConfig(t *testing.T) {
	testcases := map[string]struct {
		cfg     Elasticsearch
		url     string
		want    string
		headers map[string]string
		env     map[string]string
	}{
		"no proxy": {
			cfg: Elasticsearch{ProxyDisable: true},
		},
		"proxy url set": {
			cfg: Elasticsearch{
				ProxyURL: "http://proxy.com",
			},
			url:  "http://test.com",
			want: "http://proxy.com",
		},
		"with headers": {
			cfg: Elasticsearch{
				ProxyURL: "http://proxy.com",
				ProxyHeaders: map[string]string{
					"TestProxyHeader": "Custom Value",
				},
			},
			url:  "http://test.com",
			want: "http://proxy.com",
			headers: map[string]string{
				"TestProxyHeader": "Custom Value",
			},
		},
		"proxy from env by default": {
			cfg:  Elasticsearch{},
			url:  "http://test.com",
			want: "http://proxy.com",
			env: map[string]string{
				"HTTP_PROXY": "http://proxy.com",
			},
		},
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			_ = testlog.SetLogger(t)
			setTestEnv(t, test.env)

			res, err := test.cfg.ToESConfig(false)
			require.NoError(t, err)

			transport := res.Transport.(*http.Transport) //nolint:errcheck // test case
			if test.want == "" {
				require.Nil(t, transport.Proxy)
				return
			}
			require.NotNil(t, transport.Proxy)

			req, err := http.NewRequest("GET", test.url, nil) //nolint:noctx // test case
			require.NoError(t, err)

			got, err := transport.Proxy(req)
			require.NoError(t, err)

			if len(test.headers) == 0 {
				require.Len(t, transport.ProxyConnectHeader, 0)
			} else {
				headers := http.Header{}
				for k, v := range test.headers {
					headers.Add(k, v)
				}
				require.Equal(t, headers, transport.ProxyConnectHeader)
			}

			require.Equal(t, test.want, got.String())
		})
	}
}

func setTestEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func Test_Elasticsearch_DiagRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es := &Elasticsearch{}
	es.InitDefaults()
	es.Hosts = []string{srv.URL}

	p := es.DiagRequests(ctx)
	require.NotEmpty(t, p)
	require.Contains(t, string(p), "request 0 successful.")
}
