// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/fleet-server/v7/version"
	"github.com/elastic/go-ucfg"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCLIOverrides(t *testing.T) {
	httpEnabledExpected := true
	httpHostExpected := "sample-host"
	loggingFilesNameExpected := "fleet-server-logging"

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
		client.UnitStateHealthy,
		client.UnitLogLevelInfo,
		&proto.UnitExpectedConfig{
			Source: sampleInputConfig,
		},
	)

	mockOutputUnit := &mockClientUnit{}
	mockOutputUnit.On("Expected").Return(
		client.UnitStateHealthy,
		client.UnitLogLevelInfo,
		&proto.UnitExpectedConfig{
			Source: sampleOutputConfig,
		},
	)

	agent := &Agent{
		cliCfg:     cliConfig,
		inputUnit:  mockInputUnit,
		outputUnit: mockOutputUnit,
		agent:      clientMock,
	}

	generatedCfg, err := agent.configFromUnits()
	require.NoError(t, err)
	require.Equal(t, httpEnabledExpected, generatedCfg.HTTP.Enabled)
	require.Equal(t, httpHostExpected, generatedCfg.HTTP.Host)
	require.Equal(t, loggingFilesNameExpected, generatedCfg.Logging.Files.Name)
}

type mockClientV2 struct {
	mock.Mock
}

func (*mockClientV2) RegisterDiagnosticHook(name string, description string, filename string, contentType string, hook client.DiagnosticHook) {
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

func (u *mockClientUnit) Expected() (client.UnitState, client.UnitLogLevel, *proto.UnitExpectedConfig) {
	args := u.Called()

	return args.Get(0).(client.UnitState),
		args.Get(1).(client.UnitLogLevel),
		args.Get(2).(*proto.UnitExpectedConfig)
}
func (u *mockClientUnit) UpdateState(state client.UnitState, message string, payload map[string]interface{}) error {
	args := u.Called()
	return args.Get(0).(error)
}
