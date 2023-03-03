// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

//nolint:dupl // duplicated lines used for test cases
package config

import (
	"crypto/tls"
	"net/http"
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

	for name, test := range testcases {
		copts := cmp.Options{
			cmpopts.IgnoreUnexported(http.Transport{}),
			cmpopts.IgnoreFields(http.Transport{}, "DialContext"),
			cmpopts.IgnoreUnexported(tls.Config{}), //nolint:gosec //test case
		}
		t.Run(name, func(t *testing.T) {
			_ = testlog.SetLogger(t)
			res, err := test.cfg.ToESConfig(false)
			require.NoError(t, err)

			// cmp.Diff can't handle function pointers.
			res.Transport.(*http.Transport).Proxy = nil

			test.result.Header.Set("X-elastic-product-origin", "fleet")
			if !assert.True(t, cmp.Equal(test.result, res, copts...)) {
				diff := cmp.Diff(test.result, res, copts...)
				if diff != "" {
					t.Errorf("%s mismatch (-want +got):\n%s", name, diff)
				}
			}
		})
	}
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
