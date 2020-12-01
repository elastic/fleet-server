package config

import (
	"github.com/elastic/go-ucfg"
	"path/filepath"
	"testing"
	"time"

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
						Logging: AgentLogging{
							Level: "info",
						},
					},
				},
				Output: Output{
					Elasticsearch: Elasticsearch{
						Protocol:    "http",
						Hosts:       []string{"localhost:9200"},
						Username:    "elastic",
						Password:    "changeme",
						LoadBalance: true,
						MaxRetries:  3,
						Timeout:     90 * time.Second,
						Backoff: ElasticsearchBackoff{
							Init: 1 * time.Second,
							Max:  60 * time.Second,
						},
					},
				},
				Inputs: []Input{
					{
						Type: "fleet-server",
						Server: Server{
							Host: "0.0.0.0",
							Port: 8000,
							Timeouts: ServerTimeouts{
								Read:  5,
								Write: 60 * 10,
							},
						},
					},
				},
			},
		},
		"fleet-logging": {
			cfg: &Config{
				Fleet: Fleet{
					Agent: Agent{
						Logging: AgentLogging{
							Level: "error",
						},
					},
				},
				Output: Output{
					Elasticsearch: Elasticsearch{
						Protocol:    "http",
						Hosts:       []string{"localhost:9200"},
						Username:    "elastic",
						Password:    "changeme",
						LoadBalance: true,
						MaxRetries:  3,
						Timeout:     90 * time.Second,
						Backoff: ElasticsearchBackoff{
							Init: 1 * time.Second,
							Max:  60 * time.Second,
						},
					},
				},
				Inputs: []Input{
					{
						Type: "fleet-server",
						Server: Server{
							Host: "0.0.0.0",
							Port: 8000,
							Timeouts: ServerTimeouts{
								Read:  5,
								Write: 60 * 10,
							},
						},
					},
				},
			},
		},
		"input": {
			cfg: &Config{
				Fleet: Fleet{
					Agent: Agent{
						Logging: AgentLogging{
							Level: "info",
						},
					},
				},
				Output: Output{
					Elasticsearch: Elasticsearch{
						Protocol:    "http",
						Hosts:       []string{"localhost:9200"},
						Username:    "elastic",
						Password:    "changeme",
						LoadBalance: true,
						MaxRetries:  3,
						Timeout:     90 * time.Second,
						Backoff: ElasticsearchBackoff{
							Init: 1 * time.Second,
							Max:  60 * time.Second,
						},
					},
				},
				Inputs: []Input{
					{
						Type: "fleet-server",
						Server: Server{
							Host: "0.0.0.0",
							Port: 8000,
							Timeouts: ServerTimeouts{
								Read:  5,
								Write: 60 * 10,
							},
						},
					},
				},
			},
		},
		"input-config": {
			cfg: &Config{
				Fleet: Fleet{
					Agent: Agent{
						Logging: AgentLogging{
							Level: "info",
						},
					},
				},
				Output: Output{
					Elasticsearch: Elasticsearch{
						Protocol:    "http",
						Hosts:       []string{"localhost:9200"},
						Username:    "elastic",
						Password:    "changeme",
						LoadBalance: true,
						MaxRetries:  3,
						Timeout:     90 * time.Second,
						Backoff: ElasticsearchBackoff{
							Init: 1 * time.Second,
							Max:  60 * time.Second,
						},
					},
				},
				Inputs: []Input{
					{
						Type: "fleet-server",
						Server: Server{
							Host: "localhost",
							Port: 8888,
							Timeouts: ServerTimeouts{
								Read:  20,
								Write: 5,
							},
						},
					},
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
			err: "invalid log level; must be one of: debug, info, warning, error",
		},
		"bad-output": {
			err: "can only contain elasticsearch key",
		},
		"empty": {
			err: "cannot connect to elasticsearch without username/password",
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
