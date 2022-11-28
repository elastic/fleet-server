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

	agent := &Agent{
		cliCfg: cliConfig,
		inputUnit: &testClientUnit{
			state:    client.UnitStateHealthy,
			logLevel: client.UnitLogLevelInfo,
			config: &proto.UnitExpectedConfig{
				Source: sampleInputConfig,
			},
		},
		outputUnit: &testClientUnit{
			state:    client.UnitStateHealthy,
			logLevel: client.UnitLogLevelInfo,
			config: &proto.UnitExpectedConfig{
				Source: sampleOutputConfig,
			},
		},
		agent: testClientV2{
			agentInfo: &client.AgentInfo{
				ID:      "test-agent",
				Version: version.DefaultVersion,
			},
		},
	}

	generatedCfg, err := agent.configFromUnits()
	require.NoError(t, err)
	require.Equal(t, httpEnabledExpected, generatedCfg.HTTP.Enabled)
	require.Equal(t, httpHostExpected, generatedCfg.HTTP.Host)
	require.Equal(t, loggingFilesNameExpected, generatedCfg.Logging.Files.Name)
}

type testClientV2 struct {
	errorChan       chan error
	unitChangedChan chan client.UnitChanged
	agentInfo       *client.AgentInfo
}

func (testClientV2) RegisterDiagnosticHook(name string, description string, filename string, contentType string, hook client.DiagnosticHook) {
}

func (testClientV2) Start(ctx context.Context) error { return nil }

func (c testClientV2) Stop() {
	if c.unitChangedChan != nil {
		close(c.unitChangedChan)
	}
}

func (c testClientV2) UnitChanges() <-chan client.UnitChanged {
	return c.unitChangedChan
}

func (c testClientV2) Errors() <-chan error {
	return c.errorChan
}

func (testClientV2) Artifacts() client.ArtifactsClient {
	return nil
}

func (c testClientV2) AgentInfo() *client.AgentInfo {
	return c.agentInfo
}

type testClientUnit struct {
	state    client.UnitState
	logLevel client.UnitLogLevel
	config   *proto.UnitExpectedConfig
}

func (u testClientUnit) Expected() (client.UnitState, client.UnitLogLevel, *proto.UnitExpectedConfig) {
	return u.state, u.logLevel, u.config
}
func (testClientUnit) UpdateState(state client.UnitState, message string, payload map[string]interface{}) error {
	return nil
}
