// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package config

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/go-ucfg"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	testcases := map[string]struct {
		err string
		cfg *Config
	}{
		"basic": {
			cfg: &Config{
				Fleet: Fleet{
					Agent: Agent{
						ID:      "1e4954ce-af37-4731-9f4a-407b08e69e42",
						Logging: AgentLogging{},
					},
				},
				Output: Output{
					Elasticsearch: Elasticsearch{
						Protocol:          "http",
						Hosts:             []string{"localhost:9200"},
						Username:          "elastic",
						Password:          "changeme",
						MaxRetries:        3,
						MaxConnPerHost:    128,
						BulkFlushInterval: 250 * time.Millisecond,
						Timeout:           90 * time.Second,
					},
				},
				Inputs: []Input{
					{
						Type: "fleet-server",
						Server: Server{
							Host: kDefaultHost,
							Port: kDefaultPort,
							Timeouts: ServerTimeouts{
								Read:  5 * time.Second,
								Write: 60 * 10 * time.Second,
							},
							MaxHeaderByteSize: 8192,
							MaxEnrollPending:  64,
							RateLimitBurst:    1024,
							RateLimitInterval: 5 * time.Millisecond,
							Profile:           ServerProfile{Bind: "localhost:6060"},
						},
					},
				},
				Logging: Logging{
					Level:    "info",
					ToStderr: false,
					ToFiles:  true,
					Files:    nil,
				},
				HTTP: HTTP{
					Host: kDefaultHTTPHost,
					Port: kDefaultHTTPPort,
				},
				Cache: Cache{
					NumCounters: defaultCacheNumCounters,
					MaxCost:     defaultCacheMaxCost,
				},
			},
		},
		"fleet-logging": {
			cfg: &Config{
				Fleet: Fleet{
					Agent: Agent{
						ID: "1e4954ce-af37-4731-9f4a-407b08e69e42",
						Logging: AgentLogging{
							Level: "error",
						},
					},
				},
				Output: Output{
					Elasticsearch: Elasticsearch{
						Protocol:          "http",
						Hosts:             []string{"localhost:9200"},
						Username:          "elastic",
						Password:          "changeme",
						MaxRetries:        3,
						MaxConnPerHost:    128,
						BulkFlushInterval: 250 * time.Millisecond,
						Timeout:           90 * time.Second,
					},
				},
				Inputs: []Input{
					{
						Type: "fleet-server",
						Server: Server{
							Host: kDefaultHost,
							Port: kDefaultPort,
							Timeouts: ServerTimeouts{
								Read:  5 * time.Second,
								Write: 60 * 10 * time.Second,
							},
							MaxHeaderByteSize: 8192,
							MaxEnrollPending:  64,
							RateLimitBurst:    1024,
							RateLimitInterval: 5 * time.Millisecond,
							Profile:           ServerProfile{Bind: "localhost:6060"},
						},
					},
				},
				Logging: Logging{
					Level:    "info",
					ToStderr: false,
					ToFiles:  true,
					Files:    nil,
				},
				HTTP: HTTP{
					Host: kDefaultHTTPHost,
					Port: kDefaultHTTPPort,
				},
				Cache: Cache{
					NumCounters: defaultCacheNumCounters,
					MaxCost:     defaultCacheMaxCost,
				},
			},
		},
		"input": {
			cfg: &Config{
				Fleet: Fleet{
					Agent: Agent{
						ID:      "1e4954ce-af37-4731-9f4a-407b08e69e42",
						Logging: AgentLogging{},
					},
				},
				Output: Output{
					Elasticsearch: Elasticsearch{
						Protocol:          "http",
						Hosts:             []string{"localhost:9200"},
						Username:          "elastic",
						Password:          "changeme",
						MaxRetries:        3,
						MaxConnPerHost:    128,
						BulkFlushInterval: 250 * time.Millisecond,
						Timeout:           90 * time.Second,
					},
				},
				Inputs: []Input{
					{
						Type: "fleet-server",
						Server: Server{
							Host: kDefaultHost,
							Port: kDefaultPort,
							Timeouts: ServerTimeouts{
								Read:  5 * time.Second,
								Write: 60 * 10 * time.Second,
							},
							MaxHeaderByteSize: 8192,
							MaxEnrollPending:  64,
							RateLimitBurst:    1024,
							RateLimitInterval: 5 * time.Millisecond,
							Profile:           ServerProfile{Bind: "localhost:6060"},
						},
					},
				},
				Logging: Logging{
					Level:    "info",
					ToStderr: false,
					ToFiles:  true,
					Files:    nil,
				},
				HTTP: HTTP{
					Host: kDefaultHTTPHost,
					Port: kDefaultHTTPPort,
				},
				Cache: Cache{
					NumCounters: defaultCacheNumCounters,
					MaxCost:     defaultCacheMaxCost,
				},
			},
		},
		"input-config": {
			cfg: &Config{
				Fleet: Fleet{
					Agent: Agent{
						ID:      "1e4954ce-af37-4731-9f4a-407b08e69e42",
						Logging: AgentLogging{},
					},
				},
				Output: Output{
					Elasticsearch: Elasticsearch{
						Protocol:          "http",
						Hosts:             []string{"localhost:9200"},
						Username:          "elastic",
						Password:          "changeme",
						MaxRetries:        3,
						MaxConnPerHost:    128,
						BulkFlushInterval: 250 * time.Millisecond,
						Timeout:           90 * time.Second,
					},
				},
				Inputs: []Input{
					{
						Type: "fleet-server",
						Server: Server{
							Host: kDefaultHost,
							Port: 8888,
							Timeouts: ServerTimeouts{
								Read:  20 * time.Second,
								Write: 5 * time.Second,
							},
							MaxHeaderByteSize: 8192,
							MaxEnrollPending:  64,
							RateLimitBurst:    1024,
							RateLimitInterval: 5 * time.Millisecond,
							Profile:           ServerProfile{Bind: "localhost:6060"},
						},
					},
				},
				Logging: Logging{
					Level:    "info",
					ToStderr: false,
					ToFiles:  true,
					Files:    nil,
				},
				HTTP: HTTP{
					Host: kDefaultHTTPHost,
					Port: kDefaultHTTPPort,
				},
				Cache: Cache{
					NumCounters: defaultCacheNumCounters,
					MaxCost:     defaultCacheMaxCost,
				},
			},
		},
		"bad-input": {
			err: "input type must be fleet-server",
		},
		"bad-input-many": {
			err: "only 1 fleet-server input can be defined",
		},
		"bad-logging": {
			err: "invalid log level; must be one of: trace, debug, info, warning, error",
		},
		"bad-output": {
			err: "can only contain elasticsearch key",
		},
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("testdata", name+".yml")
			cfg, err := LoadFile(path)
			if test.err != "" {
				if err == nil {
					t.Error("no error was reported")
				} else {
					cfgErr := err.(ucfg.Error)
					require.Equal(t, test.err, cfgErr.Reason().Error())
				}
			} else {
				require.NoError(t, err)
				if !assert.True(t, cmp.Equal(test.cfg, cfg)) {
					diff := cmp.Diff(test.cfg, cfg)
					if diff != "" {
						t.Errorf("%s mismatch (-want +got):\n%s", name, diff)
					}
				}
			}
		})
	}
}
