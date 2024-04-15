// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

//nolint:dupl // duplicated lines used for test cases
package config

import (
	"crypto/tls"
	"net/http"
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

func TestMergeElasticsearchFromPolicy(t *testing.T) {
	cfg := Elasticsearch{
		Protocol:         "http",
		Hosts:            []string{"elasticsearch:9200"},
		ServiceToken:     "token",
		Timeout:          time.Second,
		MaxRetries:       1,
		MaxConnPerHost:   1,
		MaxContentLength: 1,
	}
	tests := []struct {
		name string
		pol  Elasticsearch
		res  Elasticsearch
	}{{
		name: "default policy",
		pol: Elasticsearch{
			Hosts:            []string{"localhost:9200"},
			Timeout:          DefaultElasticsearchTimeout,
			MaxRetries:       DefaultElasticsearchMaxRetries,
			MaxConnPerHost:   DefaultElasticsearchMaxConnPerHost,
			MaxContentLength: DefaultElasticsearchMaxContentLength,
		},
		res: Elasticsearch{
			Protocol:         "http",
			Hosts:            []string{"elasticsearch:9200"},
			ServiceToken:     "token",
			Timeout:          time.Second,
			MaxRetries:       1,
			MaxConnPerHost:   1,
			MaxContentLength: 1,
		},
	}, {
		name: "hosts differ",
		pol: Elasticsearch{
			Protocol:         "https",
			Hosts:            []string{"elasticsearch:9200", "other:9200"},
			Timeout:          DefaultElasticsearchTimeout,
			MaxRetries:       DefaultElasticsearchMaxRetries,
			MaxConnPerHost:   DefaultElasticsearchMaxConnPerHost,
			MaxContentLength: DefaultElasticsearchMaxContentLength,
		},
		res: Elasticsearch{
			Protocol:         "https",
			Hosts:            []string{"elasticsearch:9200", "other:9200"},
			ServiceToken:     "token",
			Timeout:          time.Second,
			MaxRetries:       1,
			MaxConnPerHost:   1,
			MaxContentLength: 1,
		},
	}, {
		name: "all non tls attributes differ",
		pol: Elasticsearch{
			Protocol:         "https",
			Hosts:            []string{"elasticsearch:9200", "other:9200"},
			Headers:          map[string]string{"custom": "value"},
			ProxyURL:         "http://proxy:8080",
			ProxyDisable:     false,
			ProxyHeaders:     map[string]string{"proxyhead": "proxyval"},
			Timeout:          time.Second * 2,
			MaxRetries:       2,
			MaxConnPerHost:   3,
			MaxContentLength: 4,
		},
		res: Elasticsearch{
			Protocol:         "https",
			Hosts:            []string{"elasticsearch:9200", "other:9200"},
			Headers:          map[string]string{"custom": "value"},
			ProxyURL:         "http://proxy:8080",
			ProxyDisable:     false,
			ProxyHeaders:     map[string]string{"proxyhead": "proxyval"},
			ServiceToken:     "token",
			Timeout:          2 * time.Second,
			MaxRetries:       2,
			MaxConnPerHost:   3,
			MaxContentLength: 4,
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := MergeElasticsearchFromPolicy(cfg, tc.pol)
			assert.Equal(t, tc.res.Protocol, res.Protocol)
			require.Len(t, res.Hosts, len(tc.res.Hosts))
			for i, host := range tc.res.Hosts {
				assert.Equalf(t, host, res.Hosts[i], "host %d does not match", i)
			}
			require.Len(t, res.Headers, len(tc.res.Headers))
			for k, v := range tc.res.Headers {
				assert.Equal(t, v, res.Headers[k])
			}
			assert.Equal(t, tc.res.ServiceToken, res.ServiceToken)
			assert.Equal(t, tc.res.ServiceTokenPath, res.ServiceTokenPath)
			assert.Equal(t, tc.res.ProxyURL, res.ProxyURL)
			assert.Equal(t, tc.res.ProxyDisable, res.ProxyDisable)
			require.Len(t, res.ProxyHeaders, len(tc.res.ProxyHeaders))
			for k, v := range tc.res.ProxyHeaders {
				assert.Equal(t, v, res.ProxyHeaders[k])
			}
			assert.Nil(t, res.TLS)
			assert.Equal(t, tc.res.MaxRetries, res.MaxRetries)
			assert.Equal(t, tc.res.MaxConnPerHost, res.MaxConnPerHost)
			assert.Equal(t, tc.res.Timeout, res.Timeout)
			assert.Equal(t, tc.res.MaxContentLength, res.MaxContentLength)
		})
	}
}

func TestMergeElasticsearchTLS(t *testing.T) {
	enabled := true
	disabled := false
	t.Run("both nil", func(t *testing.T) {
		res := mergeElasticsearchTLS(nil, nil)
		assert.Nil(t, res)
	})
	t.Run("cfg not nil", func(t *testing.T) {
		res := mergeElasticsearchTLS(&tlscommon.Config{
			Enabled:          &enabled,
			VerificationMode: tlscommon.VerifyFull,
		}, nil)
		require.NotNil(t, res)
		assert.True(t, *res.Enabled)
		assert.Equal(t, tlscommon.VerifyFull, res.VerificationMode)
	})
	t.Run("pol not nil", func(t *testing.T) {
		res := mergeElasticsearchTLS(nil, &tlscommon.Config{
			Enabled:          &enabled,
			VerificationMode: tlscommon.VerifyFull,
		})
		require.NotNil(t, res)
		assert.True(t, *res.Enabled)
		assert.Equal(t, tlscommon.VerifyFull, res.VerificationMode)
	})
	t.Run("both not nil", func(t *testing.T) {
		res := mergeElasticsearchTLS(&tlscommon.Config{
			Enabled:          &disabled,
			VerificationMode: tlscommon.VerifyFull,
		}, &tlscommon.Config{
			Enabled:          &enabled,
			VerificationMode: tlscommon.VerifyCertificate,
			Versions:         []tlscommon.TLSVersion{tlscommon.TLSVersion13},
			CipherSuites:     []tlscommon.CipherSuite{tlscommon.CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)},
			CAs:              []string{"/path/to/ca.crt"},
			Certificate: tlscommon.CertificateConfig{
				Certificate: "/path/to/cert.crt",
				Key:         "/path/to/key.crt",
			},
			CASha256:             []string{"casha256val"},
			CATrustedFingerprint: "fingerprint",
		})
		require.NotNil(t, res)
		assert.True(t, *res.Enabled)
		assert.Equal(t, tlscommon.VerifyCertificate, res.VerificationMode)
		require.Len(t, res.Versions, 1)
		assert.Equal(t, tlscommon.TLSVersion13, res.Versions[0])
		require.Len(t, res.CipherSuites, 1)
		assert.Equal(t, tlscommon.CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA), res.CipherSuites[0])
		require.Len(t, res.CAs, 1)
		assert.Equal(t, "/path/to/ca.crt", res.CAs[0])
		assert.Equal(t, "/path/to/cert.crt", res.Certificate.Certificate)
		assert.Equal(t, "/path/to/key.crt", res.Certificate.Key)
		require.Len(t, res.CASha256, 1)
		assert.Equal(t, "casha256val", res.CASha256[0])
		assert.Equal(t, "fingerprint", res.CATrustedFingerprint)
	})
}
