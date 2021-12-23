// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package config

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/elastic/beats/v7/libbeat/common/transport/tlscommon"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
						InsecureSkipVerify: true,
						MinVersion:         tls.VersionTLS11,
						MaxVersion:         tls.VersionTLS13,
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
						InsecureSkipVerify: true,
						MinVersion:         tls.VersionTLS11,
						MaxVersion:         tls.VersionTLS13,
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
			cmpopts.IgnoreUnexported(tls.Config{}),
		}
		t.Run(name, func(t *testing.T) {
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
			setTestEnv(t, test.env)

			res, err := test.cfg.ToESConfig(false)
			require.NoError(t, err)

			transport := res.Transport.(*http.Transport)
			if test.want == "" {
				require.Nil(t, transport.Proxy)
				return
			}
			require.NotNil(t, transport.Proxy)

			req, err := http.NewRequest("GET", test.url, nil)
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
	var oldEnv map[string]string
	for k := range env {
		if v := os.Getenv(k); v != "" {
			oldEnv[k] = v
		}
	}

	t.Cleanup(func() {
		for k := range env {
			if v := oldEnv[k]; v != v {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	})

	for k, v := range env {
		os.Setenv(k, v)
	}
}
