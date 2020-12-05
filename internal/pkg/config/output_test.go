// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package config

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/elastic/beats/v7/libbeat/common/transport/tlscommon"
	"github.com/elastic/go-elasticsearch/v8"
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
				Protocol:          "http",
				Hosts:             []string{"localhost:9200"},
				Username:          "elastic",
				Password:          "changeme",
				MaxRetries:        3,
				MaxConnPerHost:    128,
				BulkFlushInterval: 250 * time.Millisecond,
				Timeout:           90 * time.Second,
			},
			result: elasticsearch.Config{
				Addresses:  []string{"http://localhost:9200"},
				Username:   "elastic",
				Password:   "changeme",
				Header:     http.Header{},
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
			},
		},
		"multi-http": {
			cfg: Elasticsearch{
				Protocol: "http",
				Hosts:    []string{"localhost:9200", "other-host:9200"},
				Username: "other",
				Password: "pass",
				Headers: map[string]string{
					"X-Custom-Header": "Header-Value",
				},
				MaxRetries:        6,
				MaxConnPerHost:    256,
				BulkFlushInterval: 250 * time.Millisecond,
				Timeout:           120 * time.Second,
			},
			result: elasticsearch.Config{
				Addresses:  []string{"http://localhost:9200", "http://other-host:9200"},
				Username:   "other",
				Password:   "pass",
				Header:     http.Header{"X-Custom-Header": {"Header-Value"}},
				MaxRetries: 6,
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
				Protocol: "https",
				Hosts:    []string{"localhost:9200", "other-host:9200"},
				Username: "other",
				Password: "pass",
				Headers: map[string]string{
					"X-Custom-Header": "Header-Value",
				},
				MaxRetries:        6,
				MaxConnPerHost:    256,
				BulkFlushInterval: 250 * time.Millisecond,
				Timeout:           120 * time.Second,
				TLS: &tlscommon.Config{
					VerificationMode: tlscommon.VerifyNone,
				},
			},
			result: elasticsearch.Config{
				Addresses:  []string{"https://localhost:9200", "https://other-host:9200"},
				Username:   "other",
				Password:   "pass",
				Header:     http.Header{"X-Custom-Header": {"Header-Value"}},
				MaxRetries: 6,
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
				Protocol: "http",
				Hosts:    []string{"localhost:9200", "https://other-host:9200"},
				Username: "other",
				Password: "pass",
				Headers: map[string]string{
					"X-Custom-Header": "Header-Value",
				},
				MaxRetries:        6,
				MaxConnPerHost:    256,
				BulkFlushInterval: 250 * time.Millisecond,
				Timeout:           120 * time.Second,
				TLS: &tlscommon.Config{
					VerificationMode: tlscommon.VerifyNone,
				},
			},
			result: elasticsearch.Config{
				Addresses:  []string{"http://localhost:9200", "https://other-host:9200"},
				Username:   "other",
				Password:   "pass",
				Header:     http.Header{"X-Custom-Header": {"Header-Value"}},
				MaxRetries: 6,
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
			res, err := test.cfg.ToESConfig()
			require.NoError(t, err)
			if !assert.True(t, cmp.Equal(test.result, res, copts...)) {
				diff := cmp.Diff(test.result, res, copts...)
				if diff != "" {
					t.Errorf("%s mismatch (-want +got):\n%s", name, diff)
				}
			}
		})
	}
}
