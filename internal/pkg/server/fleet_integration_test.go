// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

//nolint:dupl,goconst // don't care about repeating code
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

const (
	serverVersion = "8.0.0"
	localhost     = "localhost"

	testWaitServerUp = 3 * time.Second

	enrollBody = `{
	    "type": "PERMANENT",
	    "shared_id": "",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`
	checkinBody = `{
	    "status": "online",
	    "message": "checkin ok"
	}`
)

type tserver struct {
	cfg       *config.Config
	g         *errgroup.Group
	srv       *Fleet
	enrollKey string
	bulker    bulk.Bulk

	outputReloadSuccess atomic.Int32
	outputReloadFailure atomic.Int32
}

func (s *tserver) baseURL() string {
	input, _ := s.cfg.GetFleetInput()
	tls := input.Server.TLS
	schema := "http"
	if tls != nil && tls.IsEnabled() {
		schema = "https"
	}
	return fmt.Sprintf("%s://%s:%d", schema, input.Server.Host, input.Server.Port)
}

func (s *tserver) waitExit() error {
	err := s.g.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}

	// FIXME: Below is a work around to net.DNSError not supporting the `Unwrap` method.
	// It is so we can ignore errors caused by context cancelation.
	// It can be removed when DNSError.Unwrap is added to the stdlib.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if strings.Contains(dnsErr.Err, "operation was canceled") {
			return nil
		}
	}

	return err
}

type Option func(cfg *config.Config) error

func WithAPM(url string, enabled bool) Option {
	return func(cfg *config.Config) error {
		cfg.Inputs[0].Server.Instrumentation = config.Instrumentation{
			Enabled: enabled,
			Hosts:   []string{url},
		}
		return nil
	}
}

func startTestServer(t *testing.T, ctx context.Context, policyD model.PolicyData, opts ...Option) (*tserver, error) {
	t.Helper()

	cfg, err := config.LoadFile("../testing/fleet-server-testing.yml")
	if err != nil {
		return nil, fmt.Errorf("config load error: %w", err)
	}

	logger.Init(cfg, "fleet-server") //nolint:errcheck // test logging setup

	bulker := ftesting.SetupBulk(ctx, t)

	policyID := uuid.Must(uuid.NewV4()).String()
	_, err = dl.CreatePolicy(ctx, bulker, model.Policy{
		PolicyID:           policyID,
		RevisionIdx:        1,
		DefaultFleetServer: true,
		Data:               &policyD,
	})
	if err != nil {
		return nil, err
	}

	// In order to create a functional enrollement token we need to use the ES endpoint to create a new api key
	// then add the key (id/value) to the enrollment index
	esCfg := elasticsearch.Config{
		Username: "elastic",
		Password: "changeme",
	}
	es, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		t.Fatal(err)
	}
	key, err := apikey.Create(ctx, es, "default", "", "true", []byte(`{
	    "fleet-apikey-enroll": {
		"cluster": [],
		"index": [],
		"applications": [{
		    "application": "fleet",
		    "privileges": ["no-privileges"],
		    "resources": ["*"]
		}]
	    }
	}`), map[string]interface{}{
		"managed_by": "fleet",
		"managed":    true,
		"type":       "enroll",
		"policy_id":  policyID,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = dl.CreateEnrollmentAPIKey(ctx, bulker, model.EnrollmentAPIKey{
		Name:     "Default",
		APIKey:   key.Key,
		APIKeyID: key.ID,
		PolicyID: policyID,
		Active:   true,
	})
	if err != nil {
		return nil, err
	}
	// sanity check
	tokens, err := dl.FindEnrollmentAPIKeys(ctx, bulker, dl.QueryEnrollmentAPIKeyByPolicyID, dl.FieldPolicyID, policyID)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no enrollment tokens found")
	}

	port, err := ftesting.FreePort()
	if err != nil {
		return nil, fmt.Errorf("unable to find port: %w", err)
	}

	srvcfg := &config.Server{}
	srvcfg.InitDefaults()
	srvcfg.Timeouts.CheckinMaxPoll = 2 * time.Minute // set to a short value for tests
	srvcfg.Host = localhost
	srvcfg.Port = port
	cfg.Inputs[0].Server = *srvcfg
	t.Logf("Test fleet server port=%d", port)

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	srv, err := NewFleet(build.Info{Version: serverVersion}, state.NewLog(), false)
	if err != nil {
		return nil, fmt.Errorf("unable to create server: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	// Since we start the server in agent mode we need a way to detect if the policy monitor has reloaded the output
	// NOTE: This code is brittle as it depends on a log string message match
	tsrv := &tserver{cfg: cfg, g: g, srv: srv, enrollKey: key.Token(), bulker: bulker}
	ctx = testlog.SetLogger(t).Hook(zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, message string) {
		if level == zerolog.InfoLevel && message == "Using output from policy" {
			tsrv.outputReloadSuccess.Add(1)
		} else if level == zerolog.WarnLevel && message == "Failed version compatibility check using output from policy" {
			tsrv.outputReloadFailure.Add(1)
		}
	})).WithContext(ctx)

	g.Go(func() error {
		return srv.Run(ctx, cfg)
	})

	err = tsrv.waitServerUp(ctx, testWaitServerUp)
	if err != nil {
		return nil, fmt.Errorf("unable to start server: %w", err)
	}
	return tsrv, nil
}

func (s *tserver) waitServerUp(ctx context.Context, dur time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	cli := cleanhttp.DefaultClient()
	isHealthy := func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+"/api/status", nil)
		if err != nil {
			return false, err
		}
		resp, err := cli.Do(req)
		if err != nil {
			return false, nil //nolint:nilerr // we want to ignore the error in this case.
		}
		defer resp.Body.Close()

		d, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		var status api.StatusAPIResponse
		err = json.Unmarshal(d, &status)
		if err != nil {
			return false, err
		}

		return status.Status == "HEALTHY", nil
	}

	// Wait for the server to be in a healthy state after
	for {
		healthy, err := isHealthy()
		if err != nil {
			return err
		}
		if healthy {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (s *tserver) buildURL(id string, cmd string) string {
	ur := "/api/fleet/agents"
	if id != "" {
		ur = path.Join(ur, id)
	}
	if cmd != "" {
		ur = path.Join(ur, cmd)
	}

	return s.baseURL() + ur
}

type MockReporter struct {
	mock.Mock
}

func (m *MockReporter) UpdateState(state client.UnitState, message string, payload map[string]interface{}) error {
	args := m.Called(state, message, payload)
	return args.Error(0)
}

func TestServerConfigErrorReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// don't use startTestServer as we need failing initial config.
	cfg, err := config.LoadFile("../testing/fleet-server-testing.yml")
	require.NoError(t, err)
	newCfg, err := config.LoadFile("../testing/fleet-server-testing.yml")
	require.NoError(t, err)

	logger.Init(cfg, "fleet-server") //nolint:errcheck // test logging setup
	bulker := ftesting.SetupBulk(ctx, t)

	policyID := uuid.Must(uuid.NewV4()).String()
	_, err = dl.CreatePolicy(ctx, bulker, model.Policy{
		PolicyID:           policyID,
		RevisionIdx:        1,
		DefaultFleetServer: true,
		Data:               &policyData,
	})
	require.NoError(t, err)

	// In order to create a functional enrollement token we need to use the ES endpoint to create a new api key
	// then add the key (id/value) to the enrollment index
	esCfg := elasticsearch.Config{
		Username: "elastic",
		Password: "changeme",
	}
	es, err := elasticsearch.NewClient(esCfg)
	require.NoError(t, err)
	key, err := apikey.Create(ctx, es, "default", "", "true", []byte(`{
	    "fleet-apikey-enroll": {
		"cluster": [],
		"index": [],
		"applications": [{
		    "application": "fleet",
		    "privileges": ["no-privileges"],
		    "resources": ["*"]
		}]
	    }
	}`), map[string]interface{}{
		"managed_by": "fleet",
		"managed":    true,
		"type":       "enroll",
		"policy_id":  policyID,
	})
	require.NoError(t, err)

	_, err = dl.CreateEnrollmentAPIKey(ctx, bulker, model.EnrollmentAPIKey{
		Name:     "Default",
		APIKey:   key.Key,
		APIKeyID: key.ID,
		PolicyID: policyID,
		Active:   true,
	})
	require.NoError(t, err)
	// sanity check
	tokens, err := dl.FindEnrollmentAPIKeys(ctx, bulker, dl.QueryEnrollmentAPIKeyByPolicyID, dl.FieldPolicyID, policyID)
	require.NoError(t, err)
	require.NotZero(t, len(tokens), "no enrollment tokens found")

	port, err := ftesting.FreePort()
	require.NoError(t, err)

	srvcfg := &config.Server{}
	srvcfg.InitDefaults()
	srvcfg.Timeouts.CheckinMaxPoll = 2 * time.Minute // set to a short value for tests
	srvcfg.Host = localhost
	srvcfg.Port = port
	cfg.Inputs[0].Server = *srvcfg
	newCfg.Inputs[0].Server = *srvcfg
	cfg.HTTP.Enabled = false
	newCfg.HTTP.Enabled = false
	t.Logf("Test fleet server port=%d", port)

	mReporter := &MockReporter{}
	srv, err := NewFleet(build.Info{Version: serverVersion}, mReporter, false)
	require.NoError(t, err)

	mReporter.On("UpdateState", client.UnitStateStarting, mock.Anything, mock.Anything).Return(nil)
	mReporter.On("UpdateState", client.UnitStateConfiguring, mock.Anything, mock.Anything).Return(nil)
	mReporter.On("UpdateState", client.UnitStateHealthy, mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
		// Call cancel to stop the server once it's healthy
		go func() {
			// FIXME: A short delay is needed here as the mock failure call on line 388 is not being detected correctly in tests
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()
	}).Return(nil)
	mReporter.On("UpdateState", client.UnitStateStopping, mock.Anything, mock.Anything).Return(nil)
	mReporter.On("UpdateState", client.UnitStateFailed, mock.MatchedBy(func(err error) bool { return errors.Is(err, context.Canceled) }), mock.Anything).Return(nil).Maybe()

	// set bad config
	cfg.Output.Elasticsearch.ServiceToken = "incorrect"

	// send good config
	err = srv.Reload(ctx, newCfg)
	require.NoError(t, err)

	// Run server with the healthy reload
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return srv.Run(ctx, cfg)
	})

	err = g.Wait()
	require.NoError(t, err)
	mReporter.AssertExpectations(t)
}

func TestServerReloadOutputOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	// Give an output that will not work - it should not use this
	cfg := config.Config{
		Output: config.Output{
			Elasticsearch: config.Elasticsearch{
				Protocol: "http",
				Hosts: []string{
					"http://fake:9200",
				},
			},
		},
		RevisionIdx: 2,
	}
	err = srv.srv.Reload(ctx, &cfg)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		if srv.outputReloadFailure.Load() > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	require.NotZero(t, srv.outputReloadFailure.Load(), "Did not detect elasticsearch output client failure")

	// Give an output that works
	cfg = config.Config{
		Output: config.Output{
			Elasticsearch: config.Elasticsearch{
				Protocol: "http",
				Hosts: []string{
					"http://localhost:9200",
					"http://other:9200",
				},
			},
		},
		RevisionIdx: 3,
	}

	successes := srv.outputReloadSuccess.Load()
	err = srv.srv.Reload(ctx, &cfg)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		if srv.outputReloadSuccess.Load() > successes {
			break
		}
		time.Sleep(time.Second)
	}
	require.Greater(t, srv.outputReloadSuccess.Load(), successes, "Did not detect elasticsearch output client success")

	cancel()
	srv.waitExit() //nolint:errcheck // test case
}

func TestServerUnauthorized(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	agentID := uuid.Must(uuid.NewV4()).String()
	cli := cleanhttp.DefaultClient()

	agenturls := []string{
		srv.buildURL(agentID, "checkin"),
		srv.buildURL(agentID, "acks"),
	}

	allurls := []string{
		srv.buildURL("", "enroll"),
	}
	allurls = append(allurls, agenturls...)

	// Expecting no authorization header error
	// Not sure if this is right response, just capturing what we have so far
	// TODO: revisit error response format
	t.Run("no auth header", func(t *testing.T) {
		for _, u := range allurls {
			req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewBuffer([]byte("{}")))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			res, err := cli.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			require.Equal(t, http.StatusUnauthorized, res.StatusCode)

			raw, _ := io.ReadAll(res.Body)
			var resp api.HTTPErrResp
			err = json.Unmarshal(raw, &resp)
			if err != nil {
				t.Fatal(err)
			}
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			diff := cmp.Diff("ErrNoAuthHeader", resp.Error)
			if diff != "" {
				t.Fatal(diff)
			}
		}
	})

	// Unauthorized, expecting error from /_security/_authenticate
	t.Run("unauthorized", func(t *testing.T) {
		for _, u := range agenturls {
			req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewBuffer([]byte("{}")))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "ApiKey ZExqY1hYWUJJUVVxWDVia2JvVGM6M05XaUt5aHBRYk9YSTRQWDg4YWp0UQ==")
			res, err := cli.Do(req)

			require.NoError(t, err)
			defer res.Body.Close()

			require.Equal(t, http.StatusUnauthorized, res.StatusCode)

			raw, _ := io.ReadAll(res.Body)
			var resp api.HTTPErrResp
			err = json.Unmarshal(raw, &resp)
			if err != nil {
				t.Fatal(err)
			}
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			diff := cmp.Diff("ErrUnauthorized", resp.Error)
			if diff != "" {
				t.Fatal(diff)
			}
		}
	})

	// Stop test server
	cancel()
	srv.waitExit() //nolint:errcheck // test case
}

func TestServerInstrumentation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracerConnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		t.Logf("Tracing server received request to: %s", req.URL.Path)
		if req.URL.Path != "/intake/v2/events" {
			return
		}
		tracerConnected <- struct{}{}
		io.Copy(io.Discard, req.Body) //nolint:errcheck // test case
		t.Log("Tracing server request complete")
	}))
	defer server.Close()

	// Start test server with instrumentation disabled
	srv, err := startTestServer(t, ctx, policyData, WithAPM(server.URL, false))
	require.NoError(t, err)

	agentID := "1e4954ce-af37-4731-9f4a-407b08e69e42"
	checkinURL := srv.buildURL(agentID, "checkin")

	newInstrumentationCfg := func(cfg config.Config, instr config.Instrumentation) { //nolint:govet // mutex should not be copied in operation (hopefully)
		cfg.Inputs[0].Server.Instrumentation = instr

		newCfg, err := srv.cfg.Merge(&cfg)
		require.NoError(t, err)

		require.NoError(t, srv.srv.Reload(ctx, newCfg))
	}

	cli := cleanhttp.DefaultClient()
	callCheckinFunc := func() {
		var Err error
		defer require.NoError(t, Err)
		for {
			req, _ := http.NewRequestWithContext(ctx, "POST", checkinURL, bytes.NewBuffer([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			res, err := cli.Do(req)
			if err == nil { // return on successful request
				t.Log("Checkin request successful")
				if res.Body != nil {
					res.Body.Close()
				}
				return
			}
			Err = err //nolint:ineffassign,staticcheck // ugly work around for error checking
			// retry after wait or cancel
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}

	// Force a transaction (fleet-server should be sending tranactions from the coordinator and monitor)
	callCheckinFunc()

	// Verify the APM tracer does not connect to the mocked APM Server.
	select {
	case <-tracerConnected:
		t.Error("APM Tracer connected to APM Server, bug in the tracing code")
	case <-time.After(5 * time.Second):
		t.Log("No APM data when tracer is disabled")
	}

	// Turn instrumentation on
	newInstrumentationCfg(*srv.cfg, config.Instrumentation{ //nolint:govet // mutex should not be copied in operation (hopefully)
		Enabled: true,
		Hosts:   []string{server.URL},
	})

	// Force a transaction
	callCheckinFunc()

	// Verify that the server now sends APM data
	select {
	case <-tracerConnected:
		t.Log("tracer connection detected")
	case <-time.After(5 * time.Second):
		t.Error("APM tracer connection undetected, bug in the tracing code")
	}

	cancel()
	require.NoError(t, srv.waitExit())
}

// Test_SmokeTest_Agent_Calls is a basic sanity test for fleet-server.
// API server creation with all middlewares apply.
//
// It tests the agent enrollement workflow.
// make an enroll request with an enrollment API key
// make a followup checkin request to get the policy action
// make another followup ack request for the action
func Test_SmokeTest_Agent_Calls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	cli := cleanhttp.DefaultClient()

	// enroll an agent
	t.Log("Enroll an agent")
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Agent enrollment successful, verify body")
	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var obj map[string]interface{} // NOTE Should we use response objects?
	err = json.Unmarshal(p, &obj)
	require.NoError(t, err)

	item, ok := obj["item"]
	require.True(t, ok, "expected attribute item is missing")
	mm, ok := item.(map[string]interface{})
	require.True(t, ok, "expected attribute item to be an object")

	id, ok := mm["id"]
	require.True(t, ok, "expected attribute id is missing")
	str, ok := id.(string)
	require.True(t, ok, "expected attribute id to be a string")
	require.NotEmpty(t, str)

	apiKey, ok := mm["access_api_key"]
	require.True(t, ok, "expected attribute access_api_key is missing")
	key, ok := apiKey.(string)
	require.True(t, ok, "expected attribute access_api_key to be a string")
	require.NotEmpty(t, key)

	// checkin
	t.Logf("Fake a checkin for agent %s", str)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+str+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+key)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Checkin successful, verify body")
	p, _ = io.ReadAll(res.Body)
	res.Body.Close()
	err = json.Unmarshal(p, &obj)
	require.NoError(t, err)

	at, ok := obj["ack_token"]
	require.True(t, ok, "expected ack_token in response")
	_, ok = at.(string)
	require.True(t, ok, "ack_token is not a string")

	actionsRaw, ok := obj["actions"]
	require.True(t, ok, "expected actions is missing")
	actions, ok := actionsRaw.([]interface{})
	require.True(t, ok, "expected actions to be an array")
	require.Greater(t, len(actions), 0, "expected at least 1 action")
	action, ok := actions[0].(map[string]interface{})
	require.True(t, ok, "expected action to be an object")
	aIDRaw, ok := action["id"]
	require.True(t, ok, "expected action id attribute missing")
	aID, ok := aIDRaw.(string)
	require.True(t, ok, "expected action id to be string")
	aAgentIDRaw, ok := action["agent_id"]
	require.True(t, ok, "expected action agent_id attribute missing")
	aAgentID, ok := aAgentIDRaw.(string)
	require.True(t, ok, "expected action agent_id to be string")
	require.Equal(t, str, aAgentID)

	body := fmt.Sprintf(`{
	    "events": [{
		"action_id": "%s",
		"agent_id": "%s",
		"message": "test-message",
		"type": "ACTION_RESULT",
		"subtype": "ACKNOWLEDGED"
	    }]
	}`, aID, str)
	t.Logf("Fake an ack for action %s for agent %s", aID, str)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+str+"/acks", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+key)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Ack successful, verify body")
	p, _ = io.ReadAll(res.Body)
	res.Body.Close()
	var ackObj map[string]interface{}
	err = json.Unmarshal(p, &ackObj)
	require.NoError(t, err)

	// NOTE the checkin response will only have the errors attribute if it's set to true in the response.
	// When decoding to a (typed) struct, the default will implicitly be false if it's missing
	_, ok = ackObj["errors"]
	require.Falsef(t, ok, "expected response to have no errors attribute, errors are present: %+v", ackObj)
}

func EnrollAgent(enrollBody string, t *testing.T, ctx context.Context, srv *tserver) (string, string) {
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")

	cli := cleanhttp.DefaultClient()
	res, err := cli.Do(req)
	require.NoError(t, err)

	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var obj map[string]interface{}
	err = json.Unmarshal(p, &obj)
	require.NoError(t, err)

	t.Log(obj)

	require.Equal(t, http.StatusOK, res.StatusCode)

	item := obj["item"]
	mm, ok := item.(map[string]interface{})
	require.True(t, ok, "expected attribute item to be an object")
	agentID := mm["id"]

	apiKey, ok := mm["access_api_key"]
	require.True(t, ok, "expected attribute access_api_key is missing")
	key, ok := apiKey.(string)
	require.True(t, ok, "expected attribute access_api_key to be a string")
	require.NotEmpty(t, key)

	return agentID.(string), key
}

func Test_Agent_Enrollment_Id(t *testing.T) {
	enrollBodyWEnrollmentID := `{
	    "type": "PERMANENT",
	    "shared_id": "",
	    "enrollment_id": "123456",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	t.Log("Enroll the first agent with enrollment_id")
	firstAgentID, _ := EnrollAgent(enrollBodyWEnrollmentID, t, ctx, srv)

	t.Log("Enroll the second agent with the same enrollment_id")
	secondAgentID, _ := EnrollAgent(enrollBodyWEnrollmentID, t, ctx, srv)

	// cleanup
	defer func() {
		err := srv.bulker.Delete(ctx, dl.FleetAgents, secondAgentID)
		if err != nil {
			t.Log("could not clean up second agent")
		}
		err2 := srv.bulker.Delete(ctx, dl.FleetAgents, firstAgentID)
		if err2 != nil {
			t.Log("could not clean up first agent")
		}
	}()

	// checking that old agent with enrollment id is deleted
	agent, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, firstAgentID)
	t.Log(agent)
	if err != nil {
		t.Log("old agent not found as expected")
	} else {
		t.Fatal("duplicate agent found after enrolling with same enrollment id")
	}
}

func Test_Agent_Enrollment_Id_Invalidated_API_key(t *testing.T) {
	enrollBodyWEnrollmentID := `{
	    "type": "PERMANENT",
	    "shared_id": "",
	    "enrollment_id": "123456invalidated",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	t.Log("Enroll the first agent with enrollment_id")
	firstAgentID, _ := EnrollAgent(enrollBodyWEnrollmentID, t, ctx, srv)

	agent, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, firstAgentID)
	if err != nil {
		t.Log("first agent not found")
	}

	// invalidate first api key to verify if second enroll works like this
	t.Log("invalidate the first agent api key")
	t.Log(agent.AccessAPIKeyID)
	if err = srv.bulker.APIKeyInvalidate(ctx, agent.AccessAPIKeyID); err != nil {
		t.Fatal("Could not invalidate API key")
	}

	t.Log("Enroll the second agent with the same enrollment_id")
	secondAgentID, _ := EnrollAgent(enrollBodyWEnrollmentID, t, ctx, srv)

	// cleanup
	defer func() {
		err := srv.bulker.Delete(ctx, dl.FleetAgents, secondAgentID)
		if err != nil {
			t.Log("could not clean up second agent")
		}
		err2 := srv.bulker.Delete(ctx, dl.FleetAgents, firstAgentID)
		if err2 != nil {
			t.Log("could not clean up first agent")
		}
	}()

	// checking that old agent with enrollment id is deleted
	agent, err = dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, firstAgentID)
	t.Log(agent)
	if err != nil {
		t.Log("old agent not found as expected")
	} else {
		t.Fatal("duplicate agent found after enrolling with same enrollment id")
	}
}

func Test_Agent_Auth_errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	cli := cleanhttp.DefaultClient()

	// Setup for some strange auth cases
	// enroll an agent, and get it's API key
	t.Log("Enroll an agent")
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var obj map[string]interface{} // NOTE Should we use response objects?
	err = json.Unmarshal(p, &obj)
	require.NoError(t, err)

	item, ok := obj["item"]
	require.True(t, ok, "expected attribute item is missing")
	mm, ok := item.(map[string]interface{})
	require.True(t, ok, "expected attribute item to be an object")
	keyRaw, ok := mm["access_api_key"]
	require.True(t, ok, "expected attribute access_api_key is missing")
	key, ok := keyRaw.(string)
	require.True(t, ok, "expected attribute access_api_key to be a string")
	require.NotEmpty(t, key)

	idRaw, ok := mm["id"]
	require.True(t, ok, "expected attribute id is missing")
	id, ok := idRaw.(string)
	require.True(t, ok, "expected attribute id to be a string")
	require.NotEmpty(t, id)

	t.Run("use enroll key for checkin", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+id+"/checkin", strings.NewReader(checkinBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")

		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusNotFound, res.StatusCode) // NOTE this is a 404 and not a 400
	})
	t.Run("wrong agent ID", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/bad-agent-id/checkin", strings.NewReader(checkinBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+key)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")

		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusForbidden, res.StatusCode)
	})
	t.Run("use another agent's api key", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")
		res, err := cli.Do(req)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)
		t.Log("Agent enrollment successful, verify body")
		p, _ := io.ReadAll(res.Body)
		res.Body.Close()
		var obj map[string]interface{} // NOTE Should we use response objects?
		err = json.Unmarshal(p, &obj)
		require.NoError(t, err)

		item, ok := obj["item"]
		require.True(t, ok, "expected attribute item is missing")
		mm, ok := item.(map[string]interface{})
		require.True(t, ok, "expected attribute item to be an object")

		idRaw, ok := mm["id"]
		require.True(t, ok, "expected attribute id is missing")
		id, ok := idRaw.(string)
		require.True(t, ok, "expected attribute id to be a string")
		require.NotEmpty(t, id)

		req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+id+"/checkin", strings.NewReader(checkinBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+key)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")

		res, err = cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusForbidden, res.StatusCode)
	})
	t.Run("use api key for enrollment", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+key)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")
		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusInternalServerError, res.StatusCode)
	})
}

func Test_Agent_request_errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	cli := cleanhttp.DefaultClient()
	t.Run("no auth", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
		require.NoError(t, err)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")
		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})
	t.Run("bad path", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/temporary", strings.NewReader(enrollBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")
		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusNotFound, res.StatusCode)
	})
	t.Run("wrong method", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "PUT", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")
		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusMethodNotAllowed, res.StatusCode)
	})
	t.Run("no body", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")
		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
	t.Run("no user agent", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
		req.Header.Set("Content-Type", "application/json")
		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
	t.Run("bad user agent", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
		req.Header.Set("User-Agent", "elastic-agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")
		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func Test_SmokeTest_CheckinPollTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	cli := cleanhttp.DefaultClient()

	// enroll an agent
	t.Log("Enroll an agent")
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	dec := json.NewDecoder(res.Body)
	var enrollResponse api.EnrollResponse
	err = dec.Decode(&enrollResponse)
	res.Body.Close()
	require.NoError(t, err)
	agentID := enrollResponse.Item.Id
	apiKey := enrollResponse.Item.AccessApiKey

	// checkin
	t.Logf("checkin 1: agent %s no poll_timeout", agentID)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	res, err = cli.Do(req)
	require.NoError(t, err)
	t.Logf("checkin 1: agent %s took %s", agentID, time.Since(start))

	require.Equal(t, http.StatusOK, res.StatusCode)
	var checkinResponse api.CheckinResponse
	dec = json.NewDecoder(res.Body)
	err = dec.Decode(&checkinResponse)
	res.Body.Close()
	require.NoError(t, err)

	t.Logf("Ack actions for agent %s", agentID)
	events := make([]api.AckRequest_Events_Item, 0, len(*checkinResponse.Actions))
	for _, action := range *checkinResponse.Actions {
		event := api.GenericEvent{
			ActionId: action.Id,
			AgentId:  agentID,
			Message:  "test-message",
			Type:     api.ACTIONRESULT,
			Subtype:  api.ACKNOWLEDGED,
		}
		ev := api.AckRequest_Events_Item{}
		err := ev.FromGenericEvent(event)
		require.NoError(t, err)
		events = append(events, ev)
	}
	p, err := json.Marshal(api.AckRequest{Events: events})
	require.NoError(t, err)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/acks", bytes.NewBuffer(p))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	t.Logf("checkin 2: agent %s poll_timeout 3m", agentID)
	ctx, cancel = context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/checkin", strings.NewReader(fmt.Sprintf(`{
	    "ack_token": "%s",
	    "status": "online",
	    "message": "checkin ok",
	    "poll_timeout": "3m"
	}`, *checkinResponse.AckToken)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	start = time.Now()
	res, err = cli.Do(req)
	require.NoError(t, err)
	dur := time.Since(start)
	t.Logf("checkin 2: agent %s took %s", agentID, time.Since(start))
	p, err = io.ReadAll(res.Body)
	res.Body.Close()
	require.NoError(t, err)
	t.Logf("Response body: %s", string(p))
	t.Logf("Request duration: %s", dur)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.LessOrEqual(t, dur, 2*time.Minute)
	err = json.Unmarshal(p, &checkinResponse)
	require.NoError(t, err)

	t.Logf("checkin 3: agent %s poll_timeout 10m checkin_max_limit returns early", agentID)
	ctx, cancel = context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/checkin", strings.NewReader(fmt.Sprintf(`{
	    "ack_token": "%s",
	    "status": "online",
	    "message": "checkin ok",
	    "poll_timeout": "10m"
	}`, *checkinResponse.AckToken)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	start = time.Now()
	res, err = cli.Do(req)
	require.NoError(t, err)
	dur = time.Since(start)
	t.Logf("checkin 3: agent %s took %s", agentID, time.Since(start))
	p, err = io.ReadAll(res.Body)
	res.Body.Close()
	require.NoError(t, err)
	t.Logf("Response body: %s", string(p))
	t.Logf("Request duration: %s", dur)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.LessOrEqual(t, dur, 3*time.Minute) // include write timeout
	require.GreaterOrEqual(t, dur, time.Minute)
}

func Test_SmokeTest_CheckinPollShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	cli := cleanhttp.DefaultClient()

	// enroll an agent
	t.Log("Enroll an agent")
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	dec := json.NewDecoder(res.Body)
	var enrollResponse api.EnrollResponse
	err = dec.Decode(&enrollResponse)
	res.Body.Close()
	require.NoError(t, err)
	agentID := enrollResponse.Item.Id
	apiKey := enrollResponse.Item.AccessApiKey

	// checkin
	t.Logf("checkin 1: agent %s no poll_timeout", agentID)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	res, err = cli.Do(req)
	require.NoError(t, err)
	t.Logf("checkin 1: agent %s took %s", agentID, time.Since(start))

	require.Equal(t, http.StatusOK, res.StatusCode)
	var checkinResponse api.CheckinResponse
	dec = json.NewDecoder(res.Body)
	err = dec.Decode(&checkinResponse)
	res.Body.Close()
	require.NoError(t, err)

	t.Logf("Ack actions for agent %s", agentID)
	events := make([]api.AckRequest_Events_Item, 0, len(*checkinResponse.Actions))
	for _, action := range *checkinResponse.Actions {
		event := api.GenericEvent{
			ActionId: action.Id,
			AgentId:  agentID,
			Message:  "test-message",
			Type:     api.ACTIONRESULT,
			Subtype:  api.ACKNOWLEDGED,
		}
		ev := api.AckRequest_Events_Item{}
		err := ev.FromGenericEvent(event)
		require.NoError(t, err)
		events = append(events, ev)
	}
	p, err := json.Marshal(api.AckRequest{Events: events})
	require.NoError(t, err)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/acks", bytes.NewBuffer(p))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	t.Logf("checkin 2: agent %s poll_timeout 3m server will shutdown after 10s", agentID)
	//nolint:noctx // we want to halt the request via the server context cancelation
	req, err = http.NewRequest("POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/checkin", strings.NewReader(fmt.Sprintf(`{
	    "ack_token": "%s",
	    "status": "online",
	    "message": "checkin ok",
	    "poll_timeout": "3m"
	}`, *checkinResponse.AckToken)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	start = time.Now()

	go func() {
		time.Sleep(time.Second * 10)
		t.Log("Shutting down server")
		cancel()
	}()
	res, err = cli.Do(req)
	require.NoError(t, err)
	dur := time.Since(start)
	t.Logf("checkin 2: agent %s took %s", agentID, time.Since(start))
	p, err = io.ReadAll(res.Body)
	res.Body.Close()
	require.NoError(t, err)
	t.Logf("Response body: %s", string(p))
	t.Logf("Request duration: %s", dur)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.LessOrEqual(t, dur, 2*time.Minute)
	require.GreaterOrEqual(t, dur, time.Second*10)
	token := *checkinResponse.AckToken
	err = json.Unmarshal(p, &checkinResponse)
	require.NoError(t, err)
	require.Equal(t, token, *checkinResponse.AckToken)
}
