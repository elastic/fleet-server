// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/elastic/fleet-server/v7/version"
	"github.com/elastic/go-ucfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCLIOverrides(t *testing.T) {
	httpEnabledExpected := true
	httpHostExpected := "sample-host"
	loggingFilesNameExpected := "fleet-server-logging"
	serviceToken := "token-test"

	cliConfig, err := ucfg.NewFrom(map[string]interface{}{
		"http": map[string]interface{}{
			"enabled": httpEnabledExpected,
			"host":    httpHostExpected,
		},
		"logging": map[string]interface{}{
			"files": map[string]interface{}{
				"name": loggingFilesNameExpected,
			},
		},
		"output": map[string]interface{}{
			"elasticsearch": map[string]interface{}{
				"service_token": serviceToken,
			},
		},
	})
	require.NoError(t, err, "failed creating CLI config")

	sampleInputConfig, err := structpb.NewStruct(map[string]interface{}{})
	require.NoError(t, err)

	sampleOutputConfig, err := structpb.NewStruct(map[string]interface{}{})
	require.NoError(t, err)

	clientMock := &mockClientV2{}
	clientMock.On("AgentInfo").Return(&client.AgentInfo{
		ID:      "test-agent",
		Version: version.DefaultVersion,
	})

	mockInputUnit := &mockClientUnit{}
	mockInputUnit.On("Expected").Return(
		client.Expected{
			State:    client.UnitStateHealthy,
			LogLevel: client.UnitLogLevelInfo,
			Config: &proto.UnitExpectedConfig{
				Source: sampleInputConfig,
			},
		},
	)

	mockOutputUnit := &mockClientUnit{}
	mockOutputUnit.On("Expected").Return(
		client.Expected{
			State:    client.UnitStateHealthy,
			LogLevel: client.UnitLogLevelInfo,
			Config: &proto.UnitExpectedConfig{
				Source: sampleOutputConfig,
			},
		},
	)

	agent := &Agent{
		cliCfg:     cliConfig,
		inputUnit:  mockInputUnit,
		outputUnit: mockOutputUnit,
		agent:      clientMock,
	}

	generatedCfg, err := agent.configFromUnits(context.Background())
	require.NoError(t, err)
	require.Equal(t, httpEnabledExpected, generatedCfg.HTTP.Enabled)
	require.Equal(t, httpHostExpected, generatedCfg.HTTP.Host)
	require.Equal(t, loggingFilesNameExpected, generatedCfg.Logging.Files.Name)
	require.Equal(t, serviceToken, generatedCfg.Output.Elasticsearch.ServiceToken)
}

type mockClientV2 struct {
	mock.Mock
}

func (*mockClientV2) RegisterDiagnosticHook(name string, description string, filename string, contentType string, hook client.DiagnosticHook) {
}

func (c *mockClientV2) RegisterOptionalDiagnosticHook(paramTag string, name string, description string, filename string, contentType string, hook client.DiagnosticHook) {
}

func (c *mockClientV2) Start(ctx context.Context) error {
	args := c.Called()
	return args.Get(0).(error)
}

func (c *mockClientV2) Stop() {}

func (c *mockClientV2) UnitChanges() <-chan client.UnitChanged {
	args := c.Called()
	return args.Get(0).(<-chan client.UnitChanged)
}

func (c *mockClientV2) Errors() <-chan error {
	args := c.Called()
	return args.Get(0).(<-chan error)
}

func (c *mockClientV2) Artifacts() client.ArtifactsClient {
	args := c.Called()
	return args.Get(0).(client.ArtifactsClient)
}

func (c *mockClientV2) AgentInfo() *client.AgentInfo {
	args := c.Called()
	return args.Get(0).(*client.AgentInfo)
}

type mockClientUnit struct {
	mock.Mock
}

func (u *mockClientUnit) Expected() client.Expected {
	args := u.Called()

	return args.Get(0).(client.Expected)
}

func (u *mockClientUnit) UpdateState(state client.UnitState, message string, payload map[string]interface{}) error {
	args := u.Called()
	return args.Get(0).(error)
}

func Test_Agent_configFromUnits(t *testing.T) {
	mockAgent := &mockClientV2{}
	mockAgent.On("AgentInfo").Return(&client.AgentInfo{
		ID:      "test-id",
		Version: "test-version",
	})
	t.Run("input has additional server keys", func(t *testing.T) {
		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"service_token": "test-token",
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})

		inStruct, err := structpb.NewStruct(map[string]interface{}{
			"type": "fleet-server",
			"server": map[string]interface{}{
				"host": "0.0.0.0",
				"timeouts": map[string]interface{}{
					"write": "29m",
				},
			},
			"server.limits.max_agents":          1000,
			"server.timeouts.checkin_long_poll": "1m",
		})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: inStruct},
			})

		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
		}

		cfg, err := a.configFromUnits(context.Background())
		require.NoError(t, err)
		require.Len(t, cfg.Inputs, 1)
		assert.Equal(t, "fleet-server", cfg.Inputs[0].Type)
		assert.Equal(t, "0.0.0.0", cfg.Inputs[0].Server.Host)
		assert.Equal(t, 29*time.Minute, cfg.Inputs[0].Server.Timeouts.Write)
		assert.Equal(t, time.Minute, cfg.Inputs[0].Server.Timeouts.CheckinLongPoll)
		assert.Equal(t, 1000, cfg.Inputs[0].Server.Limits.MaxAgents)
		assert.Equal(t, "test-token", cfg.Output.Elasticsearch.ServiceToken)
	})
	t.Run("output has multiple hosts", func(t *testing.T) {
		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"service_token": "test-token",
			"hosts":         []interface{}{"https://localhost:9200", "https://127.0.0.1:9200"},
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})
		inStruct, err := structpb.NewStruct(map[string]interface{}{"type": "fleet-server"})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: inStruct},
			})

		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
		}

		cfg, err := a.configFromUnits(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "fleet-server", cfg.Inputs[0].Type)
		require.Len(t, cfg.Output.Elasticsearch.Hosts, 2)
	})
	t.Run("APM config is specified", func(t *testing.T) {
		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"service_token": "test-token",
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})

		inStruct, err := structpb.NewStruct(map[string]interface{}{
			"type": "fleet-server",
			"server": map[string]interface{}{
				"host": "0.0.0.0",
			},
		})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: inStruct},
				APMConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Tls: &proto.ElasticAPMTLS{
							SkipVerify: false,
							ServerCa:   "/path/to/ca.crt",
						},
						Environment:  "test",
						ApiKey:       "apiKey",
						SecretToken:  "secretToken",
						Hosts:        []string{"testhost:8080"},
						GlobalLabels: "test",
					},
				},
			})

		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
		}

		cfg, err := a.configFromUnits(context.Background())
		require.NoError(t, err)
		require.Len(t, cfg.Inputs, 1)
		assert.Equal(t, "fleet-server", cfg.Inputs[0].Type)
		assert.Equal(t, "0.0.0.0", cfg.Inputs[0].Server.Host)
		assert.True(t, cfg.Inputs[0].Server.Instrumentation.Enabled)
		assert.False(t, cfg.Inputs[0].Server.Instrumentation.TLS.SkipVerify)
		assert.Equal(t, "/path/to/ca.crt", cfg.Inputs[0].Server.Instrumentation.TLS.ServerCA)
		assert.Equal(t, "test", cfg.Inputs[0].Server.Instrumentation.Environment)
		assert.Equal(t, "apiKey", cfg.Inputs[0].Server.Instrumentation.APIKey)
		assert.Equal(t, "secretToken", cfg.Inputs[0].Server.Instrumentation.SecretToken)
		assert.Equal(t, []string{"testhost:8080"}, cfg.Inputs[0].Server.Instrumentation.Hosts)
		assert.Equal(t, "test", cfg.Inputs[0].Server.Instrumentation.GlobalLabels)
		assert.Equal(t, "test-token", cfg.Output.Elasticsearch.ServiceToken)
	})
	t.Run("APM config no tls", func(t *testing.T) {
		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"service_token": "test-token",
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})

		inStruct, err := structpb.NewStruct(map[string]interface{}{
			"type": "fleet-server",
			"server": map[string]interface{}{
				"host": "0.0.0.0",
			},
		})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: inStruct},
				APMConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Environment:  "test",
						ApiKey:       "apiKey",
						SecretToken:  "secretToken",
						Hosts:        []string{"testhost:8080"},
						GlobalLabels: "test",
					},
				},
			})

		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
		}

		cfg, err := a.configFromUnits(context.Background())
		require.NoError(t, err)
		require.Len(t, cfg.Inputs, 1)
		assert.Equal(t, "fleet-server", cfg.Inputs[0].Type)
		assert.Equal(t, "0.0.0.0", cfg.Inputs[0].Server.Host)
		assert.True(t, cfg.Inputs[0].Server.Instrumentation.Enabled)
		assert.False(t, cfg.Inputs[0].Server.Instrumentation.TLS.SkipVerify)
		assert.Empty(t, cfg.Inputs[0].Server.Instrumentation.TLS.ServerCA)
		assert.Equal(t, "test", cfg.Inputs[0].Server.Instrumentation.Environment)
		assert.Equal(t, "apiKey", cfg.Inputs[0].Server.Instrumentation.APIKey)
		assert.Equal(t, "secretToken", cfg.Inputs[0].Server.Instrumentation.SecretToken)
		assert.Equal(t, []string{"testhost:8080"}, cfg.Inputs[0].Server.Instrumentation.Hosts)
		assert.Equal(t, "test", cfg.Inputs[0].Server.Instrumentation.GlobalLabels)
		assert.Equal(t, "test-token", cfg.Output.Elasticsearch.ServiceToken)
	})
	t.Run("APM config and instrumentation is specified", func(t *testing.T) {
		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"service_token": "test-token",
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})

		inStruct, err := structpb.NewStruct(map[string]interface{}{
			"type": "fleet-server",
			"server": map[string]interface{}{
				"host": "0.0.0.0",
				"instrumentation": map[string]interface{}{
					"enabled": false,
					"tls": map[string]interface{}{
						"skip_verify":        true,
						"server_certificate": "/path/to/cert.crt",
					},
					"environment":  "replace",
					"api_key":      "replace",
					"secret_token": "replace",
					"hosts":        []interface{}{"replace"},
				},
			},
		})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: inStruct},
				APMConfig: &proto.APMConfig{
					Elastic: &proto.ElasticAPM{
						Tls: &proto.ElasticAPMTLS{
							SkipVerify: false,
							ServerCa:   "/path/to/ca.crt",
						},
						Environment:  "test",
						ApiKey:       "apiKey",
						SecretToken:  "secretToken",
						Hosts:        []string{"testhost:8080"},
						GlobalLabels: "test",
					},
				},
			})

		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
		}

		cfg, err := a.configFromUnits(context.Background())
		require.NoError(t, err)
		require.Len(t, cfg.Inputs, 1)
		assert.Equal(t, "fleet-server", cfg.Inputs[0].Type)
		assert.Equal(t, "0.0.0.0", cfg.Inputs[0].Server.Host)
		assert.True(t, cfg.Inputs[0].Server.Instrumentation.Enabled)
		assert.False(t, cfg.Inputs[0].Server.Instrumentation.TLS.SkipVerify)
		assert.Equal(t, "/path/to/ca.crt", cfg.Inputs[0].Server.Instrumentation.TLS.ServerCA)
		assert.Empty(t, cfg.Inputs[0].Server.Instrumentation.TLS.ServerCertificate, "expected use only config from APMConfig")
		assert.Equal(t, "test", cfg.Inputs[0].Server.Instrumentation.Environment)
		assert.Equal(t, "apiKey", cfg.Inputs[0].Server.Instrumentation.APIKey)
		assert.Equal(t, "secretToken", cfg.Inputs[0].Server.Instrumentation.SecretToken)
		assert.Equal(t, []string{"testhost:8080"}, cfg.Inputs[0].Server.Instrumentation.Hosts)
		assert.Equal(t, "test", cfg.Inputs[0].Server.Instrumentation.GlobalLabels)
		assert.Equal(t, "test-token", cfg.Output.Elasticsearch.ServiceToken)
	})
	t.Run("APM config error", func(t *testing.T) {
		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"service_token": "test-token",
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})

		inStruct, err := structpb.NewStruct(map[string]interface{}{
			"type": "fleet-server",
			"server": map[string]interface{}{
				"host": "0.0.0.0",
			},
		})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:     client.UnitStateHealthy,
				LogLevel:  client.UnitLogLevelInfo,
				Config:    &proto.UnitExpectedConfig{Source: inStruct},
				APMConfig: &proto.APMConfig{},
			})

		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
		}

		cfg, err := a.configFromUnits(context.Background())
		require.NoError(t, err)
		require.Len(t, cfg.Inputs, 1)
		assert.Equal(t, "fleet-server", cfg.Inputs[0].Type)
		assert.Equal(t, "0.0.0.0", cfg.Inputs[0].Server.Host)
		assert.False(t, cfg.Inputs[0].Server.Instrumentation.Enabled)
		assert.Equal(t, "test-token", cfg.Output.Elasticsearch.ServiceToken)
	})
	t.Run("no APMConfig has instrumentation config", func(t *testing.T) {
		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"service_token": "test-token",
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{

				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})

		inStruct, err := structpb.NewStruct(map[string]interface{}{
			"type": "fleet-server",
			"server": map[string]interface{}{
				"host": "0.0.0.0",
				"instrumentation": map[string]interface{}{
					"enabled": true,
					"tls": map[string]interface{}{
						"skip_verify":        false,
						"server_certificate": "/path/to/cert.crt",
					},
					"environment":  "test",
					"secret_token": "testToken",
					"hosts":        []interface{}{"localhost:8080"},
				},
			},
		})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: inStruct},
			})

		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
		}

		cfg, err := a.configFromUnits(context.Background())
		require.NoError(t, err)
		require.Len(t, cfg.Inputs, 1)
		assert.Equal(t, "fleet-server", cfg.Inputs[0].Type)
		assert.Equal(t, "0.0.0.0", cfg.Inputs[0].Server.Host)
		assert.True(t, cfg.Inputs[0].Server.Instrumentation.Enabled)
		assert.False(t, cfg.Inputs[0].Server.Instrumentation.TLS.SkipVerify)
		assert.Equal(t, "/path/to/cert.crt", cfg.Inputs[0].Server.Instrumentation.TLS.ServerCertificate)
		assert.Equal(t, "test", cfg.Inputs[0].Server.Instrumentation.Environment)
		assert.Empty(t, cfg.Inputs[0].Server.Instrumentation.APIKey)
		assert.Equal(t, "testToken", cfg.Inputs[0].Server.Instrumentation.SecretToken)
		assert.Equal(t, []string{"localhost:8080"}, cfg.Inputs[0].Server.Instrumentation.Hosts)
		assert.Empty(t, cfg.Inputs[0].Server.Instrumentation.GlobalLabels)
		assert.Equal(t, "test-token", cfg.Output.Elasticsearch.ServiceToken)
	})
	t.Run("output with bootstrap succeeds", func(t *testing.T) {
		// fake an ES server's version check response
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-elastic-product", "Elasticsearch")
			_, err := w.Write([]byte(`{"version":{"number":"8.0.0"}}`))
			require.NoError(t, err)
		}))
		defer srv.Close()

		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"bootstrap": map[string]interface{}{
				"service_token": "test-token",
				"hosts":         []interface{}{"https://127.0.0.1:9200"},
			},
			"hosts": []interface{}{srv.URL, "https://127.0.0.1:9200"},
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})
		inStruct, err := structpb.NewStruct(map[string]interface{}{"type": "fleet-server"})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: inStruct},
			})
		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
			bi: build.Info{
				Version: "8.0.0",
			},
		}

		ctx := testlog.SetLogger(t).WithContext(context.Background())
		cfg, err := a.configFromUnits(ctx)
		require.NoError(t, err)
		assert.Equal(t, "test-token", cfg.Output.Elasticsearch.ServiceToken)
		assert.Equal(t, []string{srv.URL, "https://127.0.0.1:9200"}, cfg.Output.Elasticsearch.Hosts)
	})
	t.Run("output with bootstrap fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-elastic-product", "Elasticsearch")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, err := w.Write([]byte(`{"version":{"number":"8.0.0"}}`))
			require.NoError(t, err)
		}))
		defer srv.Close()

		outStruct, err := structpb.NewStruct(map[string]interface{}{
			"bootstrap": map[string]interface{}{
				"service_token": "test-token",
				"hosts":         []interface{}{"https://127.0.0.1:9200"},
			},
			"hosts": []interface{}{srv.URL, "https://127.0.0.1:9200"},
		})
		require.NoError(t, err)
		mockOutClient := &mockClientUnit{}
		mockOutClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: outStruct},
			})
		inStruct, err := structpb.NewStruct(map[string]interface{}{"type": "fleet-server"})
		require.NoError(t, err)
		mockInClient := &mockClientUnit{}
		mockInClient.On("Expected").Return(
			client.Expected{
				State:    client.UnitStateHealthy,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Source: inStruct},
			})
		a := &Agent{
			cliCfg:     ucfg.New(),
			agent:      mockAgent,
			inputUnit:  mockInClient,
			outputUnit: mockOutClient,
			bi: build.Info{
				Version: "8.0.0",
			},
		}

		ctx := testlog.SetLogger(t).WithContext(context.Background())
		cfg, err := a.configFromUnits(ctx)
		require.NoError(t, err)
		assert.Equal(t, "test-token", cfg.Output.Elasticsearch.ServiceToken)
		assert.Equal(t, []string{"https://127.0.0.1:9200"}, cfg.Output.Elasticsearch.Hosts)
	})
}

func TestInjectMissingOutputAttributes(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]interface{}
		expect map[string]interface{}
	}{{
		name:  "empty input",
		input: map[string]interface{}{},
		expect: map[string]interface{}{
			"protocol":      "https",
			"hosts":         []interface{}{"localhost:9200"},
			"service_token": "token",
			"ssl": map[string]interface{}{
				"verification_mode": "full",
			},
		},
	}, {
		name: "all keys differ",
		input: map[string]interface{}{
			"NewSetting": 4,
			"NewMap": map[string]interface{}{
				"key": "val",
			},
		},
		expect: map[string]interface{}{
			"NewSetting": 4,
			"NewMap": map[string]interface{}{
				"key": "val",
			},
			"protocol":      "https",
			"hosts":         []interface{}{"localhost:9200"},
			"service_token": "token",
			"ssl": map[string]interface{}{
				"verification_mode": "full",
			},
		},
	}, {
		name: "input has same key",
		input: map[string]interface{}{
			"hosts": []interface{}{"localhost:9200", "elasticsearch:9200"},
		},
		expect: map[string]interface{}{
			"protocol":      "https",
			"hosts":         []interface{}{"localhost:9200", "elasticsearch:9200"},
			"service_token": "token",
			"ssl": map[string]interface{}{
				"verification_mode": "full",
			},
		},
	}, {
		name: "input has empty ssl object",
		input: map[string]interface{}{
			"ssl": map[string]interface{}{},
		},
		expect: map[string]interface{}{
			"protocol":      "https",
			"hosts":         []interface{}{"localhost:9200"},
			"service_token": "token",
			"ssl": map[string]interface{}{
				"verification_mode": "full",
			},
		},
	}, {
		name: "input has ssl object with same key",
		input: map[string]interface{}{
			"ssl": map[string]interface{}{
				"certificate":       "cert",
				"key":               "key",
				"verification_mode": "none",
			},
		},
		expect: map[string]interface{}{
			"protocol":      "https",
			"hosts":         []interface{}{"localhost:9200"},
			"service_token": "token",
			"ssl": map[string]interface{}{
				"certificate":       "cert",
				"key":               "key",
				"verification_mode": "none",
			},
		},
	}}
	bootstrap := map[string]interface{}{
		"protocol":      "https",
		"hosts":         []interface{}{"localhost:9200"},
		"service_token": "token",
		"ssl": map[string]interface{}{
			"verification_mode": "full",
		},
		"ignoredKey": "badValue",
		"ignoredMap": map[string]interface{}{
			"key": "value",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			injectMissingOutputAttributes(tc.input, bootstrap)
			assert.Equal(t, len(tc.expect), len(tc.input), "expected map sizes don't match")
			assert.Equal(t, tc.expect, tc.input)
		})
	}
}
