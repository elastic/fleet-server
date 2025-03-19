// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration && requirefips

package config

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/elastic/go-elasticsearch/v8"
)

func TestToESConfigTLS(t *testing.T) {
	testcases := map[string]struct {
		cfg    Elasticsearch
		result elasticsearch.Config
	}{
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
						MinVersion:         tls.VersionTLS12,
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
						MinVersion:         tls.VersionTLS12,
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
}
