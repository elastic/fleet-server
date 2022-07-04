// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

//nolint:unused // some unused code may be added to more tests
package fleet

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/server"
	"github.com/elastic/go-ucfg"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/suite"
)

var biInfo = build.Info{
	Version: "1.0.0",
	Commit:  "integration",
}

var policyData = []byte(`
{
	"inputs": [
		{
			"type": "fleet-server"
		}
	]
}
`)

var initialCfgData = `
output:
  elasticsearch:
    hosts: '${ELASTICSEARCH_HOSTS:localhost:9200}'
    service_token: '${ELASTICSEARCH_SERVICE_TOKEN}'
`

var agentIDCfgData = `
output:
  elasticsearch:
    hosts: '${ELASTICSEARCH_HOSTS:localhost:9200}'
    service_token: '${ELASTICSEARCH_SERVICE_TOKEN}'
fleet:
  agent:
    id: 1e4954ce-af37-4731-9f4a-407b08e69e42
`

var badCfgData = `
output:
  elasticsearch:
    hosts: 'localhost:63542'
    service_token: '${ELASTICSEARCH_SERVICE_TOKEN}'
fleet:
  agent:
    id: 1e4954ce-af37-4731-9f4a-407b08e69e42
`

type agentSuite struct {
	suite.RunningSuite
}

func (s *agentSuite) TestAgentMode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bulker := ftesting.SetupBulk(ctx, t)

	// add a real default fleet server policy
	policyID := uuid.Must(uuid.NewV4()).String()
	_, err := dl.CreatePolicy(ctx, bulker, model.Policy{
		PolicyID:           policyID,
		RevisionIdx:        1,
		DefaultFleetServer: true,
		Data:               policyData,
	})
	require.NoError(t, err)

	// add entry for enrollment key (doesn't have to be a real key)
	_, err = dl.CreateEnrollmentAPIKey(ctx, bulker, model.EnrollmentAPIKey{
		Name:     "Default",
		APIKey:   "keyvalue",
		APIKeyID: "keyid",
		PolicyID: policyID,
		Active:   true,
	})
	require.NoError(t, err)

	app := &StubApp{}
	control := createAndStartControlServer(t, app)
	defer control.Stop()
	appState, err := control.Register(app, initialCfgData)
	require.NoError(t, err)

	r, w := io.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		agent, err := NewAgentMode(ucfg.New(), r, biInfo)
		require.NoError(t, err)
		err = agent.Run(ctx)
		assert.NoError(t, err)
	}()

	err = appState.WriteConnInfo(w)
	require.NoError(t, err)

	// wait for fleet-server to report as degraded (starting mode without agent.id)
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status := app.Status()
		if status != proto.StateObserved_DEGRADED {
			return fmt.Errorf("should be reported as degraded; instead its %s", status)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// reconfigure with agent ID set
	err = appState.UpdateConfig(agentIDCfgData)
	require.NoError(t, err)

	// wait for fleet-server to report as healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status := app.Status()
		if status != proto.StateObserved_HEALTHY {
			return fmt.Errorf("should be reported as healthy; instead its %s", status)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// trigger update with bad configuration
	err = appState.UpdateConfig(badCfgData)
	require.NoError(t, err)

	// wait for fleet-server to report as failed
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status := app.Status()
		if status != proto.StateObserved_FAILED {
			return fmt.Errorf("should be reported as failed; instead its %s", status)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// reconfigure to good config
	err = appState.UpdateConfig(agentIDCfgData)
	require.NoError(t, err)

	// wait for fleet-server to report as healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status := app.Status()
		if status != proto.StateObserved_HEALTHY {
			return fmt.Errorf("should be reported as healthy; instead its %s", status)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// trigger stop
	err = appState.Stop(10 * time.Second)
	assert.NoError(t, err)

	// wait for go routine to exit
	wg.Wait()
}

func newDebugLogger(t *testing.T) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.DebugLevel

	log, err := logger.NewFromConfig("", loggerCfg, false)
	require.NoError(t, err)
	return log
}

func createAndStartControlServer(t *testing.T, handler server.Handler, extraConfigs ...func(*server.Server)) *server.Server {
	t.Helper()
	srv, err := server.New(newDebugLogger(t), "localhost:0", handler, nil)
	require.NoError(t, err)
	for _, extra := range extraConfigs {
		extra(srv)
	}
	require.NoError(t, srv.Start())
	return srv
}

type StubApp struct {
	lock    sync.RWMutex
	status  proto.StateObserved_Status
	message string
	payload map[string]interface{}
}

func (a *StubApp) Status() proto.StateObserved_Status {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.status
}

func (a *StubApp) Message() string {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.message
}

func (a *StubApp) OnStatusChange(_ *server.ApplicationState, status proto.StateObserved_Status, message string, payload map[string]interface{}) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.status = status
	a.message = message
	a.payload = payload
}
