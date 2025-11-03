// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

//nolint:dupl,goconst // don't care about repeating code
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/go-elasticsearch/v8"

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
	    "message": "checkin ok",
		"local_metadata": {
			"elastic": {
				"agent": {
					"version":"9.3.0"
				}
			}
		},
		"components": [
			{
				"id": "filestream-default",
				"status": "Healthy",
				"message": "Healthy"
			}
		]
	}`
)

type tserver struct {
	cfg       *config.Config
	g         *errgroup.Group
	srv       *Fleet
	enrollKey string
	bulker    bulk.Bulk
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

	l := zerolog.Nop()
	srv, err := NewFleet(build.Info{Version: serverVersion}, state.NewLog(&l), false)
	if err != nil {
		return nil, fmt.Errorf("unable to create server: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return srv.Run(ctx, cfg)
	})

	tsrv := &tserver{cfg: cfg, g: g, srv: srv, enrollKey: key.Token(), bulker: bulker}
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
			return false, nil
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
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// don't use startTestServer as we need failing initial config.
	cfg, err := config.LoadFile("../testing/fleet-server-testing.yml")
	require.NoError(t, err)
	newCfg, err := config.LoadFile("../testing/fleet-server-testing.yml")
	require.NoError(t, err)

	logger.Init(cfg, "fleet-server") //nolint:errcheck // test logging setup
	ctx = testlog.SetLogger(t).WithContext(ctx)
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
		cancel()
	}).Return(nil)
	mReporter.On("UpdateState", client.UnitStateStopping, mock.Anything, mock.Anything).Return(nil)

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

func TestServerUnauthorized(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)
	ctx = testlog.SetLogger(t).WithContext(ctx)

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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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

func stubAPMServer(t *testing.T, ch chan<- struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		t.Logf("Tracing server received request to: %s", req.URL.Path)
		if req.URL.Path != "/intake/v2/events" {
			return
		}
		ch <- struct{}{}
		io.Copy(io.Discard, req.Body) //nolint:errcheck // test case
		t.Log("Tracing server request complete")
	})
}

func TestServerInstrumentation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tracerConnected := make(chan struct{}, 1)
	server := httptest.NewServer(stubAPMServer(t, tracerConnected))
	defer server.Close()

	// Start test server with instrumentation disabled
	srv, err := startTestServer(t, ctx, policyData, WithAPM(server.URL, false))
	require.NoError(t, err)
	ctx = testlog.SetLogger(t).WithContext(ctx)

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

	// Force a transaction (fleet-server should be sending tranactions from monitor)
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
	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

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

func EnrollAgent(t *testing.T, ctx context.Context, srv *tserver, enrollBody string) api.EnrollResponse {
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")

	cli := cleanhttp.DefaultClient()
	res, err := cli.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)

	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var response api.EnrollResponse
	err = json.Unmarshal(p, &response)
	require.NoError(t, err)

	t.Log(response)

	return response
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

	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	t.Log("Enroll the first agent with enrollment_id")
	firstEnroll := EnrollAgent(t, ctx, srv, enrollBodyWEnrollmentID)

	t.Log("Enroll the second agent with the same enrollment_id")
	secondEnroll := EnrollAgent(t, ctx, srv, enrollBodyWEnrollmentID)

	// cleanup
	defer func() {
		err := srv.bulker.Delete(ctx, dl.FleetAgents, firstEnroll.Item.Id)
		if err != nil {
			t.Log("could not clean up second agent")
		}
		err2 := srv.bulker.Delete(ctx, dl.FleetAgents, secondEnroll.Item.Id)
		if err2 != nil {
			t.Log("could not clean up first agent")
		}
	}()

	// checking that old agent with enrollment id is deleted
	agent, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, firstEnroll.Item.Id)
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

	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	t.Log("Enroll the first agent with enrollment_id")
	firstEnroll := EnrollAgent(t, ctx, srv, enrollBodyWEnrollmentID)

	agent, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, firstEnroll.Item.Id)
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
	secondEnroll := EnrollAgent(t, ctx, srv, enrollBodyWEnrollmentID)

	// cleanup
	defer func() {
		err := srv.bulker.Delete(ctx, dl.FleetAgents, secondEnroll.Item.Id)
		if err != nil {
			t.Log("could not clean up second agent")
		}
		err2 := srv.bulker.Delete(ctx, dl.FleetAgents, firstEnroll.Item.Id)
		if err2 != nil {
			t.Log("could not clean up first agent")
		}
	}()

	// checking that old agent with enrollment id is deleted
	agent, err = dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, firstEnroll.Item.Id)
	t.Log(agent)
	if err != nil {
		t.Log("old agent not found as expected")
	} else {
		t.Fatal("duplicate agent found after enrolling with same enrollment id")
	}
}

func Test_Agent_Id_No_ReplaceToken(t *testing.T) {
	enrollBodyWID := `{
	    "type": "PERMANENT",
	    "id": "123456",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`

	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	t.Log("Enroll the first agent with id")
	firstEnroll := EnrollAgent(t, ctx, srv, enrollBodyWID)

	// cleanup
	defer func() {
		err := srv.bulker.Delete(ctx, dl.FleetAgents, firstEnroll.Item.Id)
		if err != nil {
			t.Log("could not clean up agent")
		}
	}()

	t.Log("Enroll the second agent with the same id")
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBodyWID))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")

	cli := cleanhttp.DefaultClient()
	res, err := cli.Do(req)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusForbidden, res.StatusCode)
}

func Test_Agent_Id_ReplaceToken_Mismatch(t *testing.T) {
	enrollBodyWID := `{
	    "type": "PERMANENT",
	    "id": "123456",
		"replace_token": "replaceable",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`

	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	t.Log("Enroll the first agent with id")
	firstEnroll := EnrollAgent(t, ctx, srv, enrollBodyWID)

	// cleanup
	defer func() {
		err := srv.bulker.Delete(ctx, dl.FleetAgents, firstEnroll.Item.Id)
		if err != nil {
			t.Log("could not clean up agent")
		}
	}()

	t.Log("Enroll the second agent with the same id")
	//nolint:gosec // disable G101
	enrollBodyBadReplaceToken := `{
	    "type": "PERMANENT",
	    "id": "123456",
		"replace_token": "replaceable_wrong",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBodyBadReplaceToken))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")

	cli := cleanhttp.DefaultClient()
	res, err := cli.Do(req)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusForbidden, res.StatusCode)
}

func Test_Agent_Id(t *testing.T) {
	enrollBodyWID := `{
	    "type": "PERMANENT",
	    "id": "123456",
		"replace_token": "replaceable",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`

	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	t.Log("Enroll the first agent with id")
	firstEnroll := EnrollAgent(t, ctx, srv, enrollBodyWID)

	t.Log("Enroll the second agent with the same id")
	secondEnroll := EnrollAgent(t, ctx, srv, enrollBodyWID)

	// cleanup
	defer func() {
		err := srv.bulker.Delete(ctx, dl.FleetAgents, firstEnroll.Item.Id)
		if err != nil {
			t.Log("could not clean up agent")
		}
	}()

	// check that the id's are expected values
	if firstEnroll.Item.Id != "123456" {
		t.Fatal("agent id is not expect value")
	}
	if firstEnroll.Item.Id != secondEnroll.Item.Id {
		t.Fatal("agent id does not match")
	}

	// check that the access key id's don't match
	if firstEnroll.Item.AccessApiKeyId == secondEnroll.Item.AccessApiKeyId {
		t.Fatal("agent access key id's should not match")
	}

	// checking that updated agent has the access key ID from the second agent
	agent, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, firstEnroll.Item.Id)
	if err != nil {
		t.Fatalf("could not find agent with id %s: %s", firstEnroll.Item.Id, err)
	}
	t.Log(agent)
	if agent.AccessAPIKeyID != secondEnroll.Item.AccessApiKeyId {
		t.Fatal("saved agent access key ID should be for the second enroll call")
	}
}

func Test_Agent_Auth_errors(t *testing.T) {
	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

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
		ctx := testlog.SetLogger(t).WithContext(ctx)
		req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+id+"/checkin", strings.NewReader(checkinBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
		req.Header.Set("User-Agent", "elastic agent "+serverVersion)
		req.Header.Set("Content-Type", "application/json")

		res, err := cli.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusForbidden, res.StatusCode)
	})
	t.Run("wrong agent ID", func(t *testing.T) {
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	cli := cleanhttp.DefaultClient()
	t.Run("no auth", func(t *testing.T) {
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
		ctx := testlog.SetLogger(t).WithContext(ctx)
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
	// Start test server
	srv, err := startTestServer(t, t.Context(), policyData)
	require.NoError(t, err)
	ctx := testlog.SetLogger(t).WithContext(t.Context())

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
	events := make([]api.AckRequest_Events_Item, 0, len(checkinResponse.Actions))
	for _, action := range checkinResponse.Actions {
		event := api.GenericEvent{
			ActionId: action.Id,
			AgentId:  agentID,
			Message:  "test-message",
			Type:     api.ACTIONRESULT,
			Subtype:  api.EventSubtypeACKNOWLEDGED,
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
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
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
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)
	ctx = testlog.SetLogger(t).WithContext(ctx)

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
	events := make([]api.AckRequest_Events_Item, 0, len(checkinResponse.Actions))
	for _, action := range checkinResponse.Actions {
		event := api.GenericEvent{
			ActionId: action.Id,
			AgentId:  agentID,
			Message:  "test-message",
			Type:     api.ACTIONRESULT,
			Subtype:  api.EventSubtypeACKNOWLEDGED,
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

// Test_SmokeTest_Verify_v85Migrate will ensure that the policy regenerates output keys when the agent doc contains an empty key
func Test_SmokeTest_Verify_v85Migrate(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	cli := cleanhttp.DefaultClient()

	// enroll an agent
	enrollBody := `{
	    "type": "PERMANENT",
	    "shared_id": "",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`
	t.Log("Enroll an agent")
	resp := EnrollAgent(t, ctx, srv, enrollBody)

	// checkin
	t.Logf("Fake a checkin for agent %s", resp.Item.Id)
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+resp.Item.Id+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+resp.Item.AccessApiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Checkin successful, verify body")
	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var obj map[string]interface{}
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
	require.Equal(t, resp.Item.Id, aAgentID)

	body := fmt.Sprintf(`{
	    "events": [{
		"action_id": "%s",
		"agent_id": "%s",
		"message": "test-message",
		"type": "ACTION_RESULT",
		"subtype": "ACKNOWLEDGED"
	    }]
	}`, aID, resp.Item.Id)
	t.Logf("Fake an ack for action %s for agent %s", aID, resp.Item.Id)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+resp.Item.Id+"/acks", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+resp.Item.AccessApiKey)
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

	// Update agent doc to have output key == ""
	agent, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, resp.Item.Id)
	require.NoError(t, err)
	outputNames := make([]string, 0, len(agent.Outputs))
	for name := range agent.Outputs {
		outputNames = append(outputNames, name)
	}
	require.Len(t, outputNames, 1)
	p = []byte(fmt.Sprintf(`{"script":{"lang": "painless", "source": "ctx._source['outputs'][params.output].api_key = ''; ctx._source['outputs'][params.output].api_key_id = '';", "params": {"output": "%s"}}}`, outputNames[0]))
	t.Logf("Attempting to remove api_key attribute from: %s, body: %s", resp.Item.Id, string(p))
	err = srv.bulker.Update(
		ctx,
		dl.FleetAgents,
		resp.Item.Id,
		p,
		bulk.WithRefresh(),
		bulk.WithRetryOnConflict(3),
	)
	require.NoError(t, err)

	// Checkin again to get policy change action and new keys
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+resp.Item.Id+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+resp.Item.AccessApiKey)
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

	at, ok = obj["ack_token"]
	require.True(t, ok, "expected ack_token in response")
	_, ok = at.(string)
	require.True(t, ok, "ack_token is not a string")

	actionsRaw, ok = obj["actions"]
	require.True(t, ok, "expected actions is missing")
	actions, ok = actionsRaw.([]interface{})
	require.True(t, ok, "expected actions to be an array")
	require.Greater(t, len(actions), 0, "expected at least 1 action")

	cancel()
	srv.waitExit() //nolint:errcheck // test case
}

func Test_SmokeTest_AuditUnenroll(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	cli := cleanhttp.DefaultClient()

	// enroll an agent
	enrollBody := `{
	    "type": "PERMANENT",
	    "shared_id": "",
	    "metadata": {
		"user_provided": {},
		"local": {},
		"tags": []
	    }
	}`
	t.Log("Enroll an agent")
	resp := EnrollAgent(t, ctx, srv, enrollBody)

	t.Logf("Use audit/unenroll endpoint for agent %s", resp.Item.Id)
	orphanBody := `{
          "reason": "orphaned",
	  "timestamp": "2024-01-01T12:00:00.000Z"
	}`
	uninstallBody := `{
          "reason": "uninstall",
	  "timestamp": "2024-01-01T12:00:00.000Z"
	}`
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+resp.Item.Id+"/audit/unenroll", strings.NewReader(uninstallBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+resp.Item.AccessApiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	res.Body.Close()

	t.Log("Orphaned can replace uninstall")
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+resp.Item.Id+"/audit/unenroll", strings.NewReader(orphanBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+resp.Item.AccessApiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	res.Body.Close()

	t.Log("Use of audit/unenroll once orphaned should fail.")
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+resp.Item.Id+"/audit/unenroll", strings.NewReader(orphanBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+resp.Item.AccessApiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, res.StatusCode)
	res.Body.Close()

	t.Logf("Fake a checkin for agent %s", resp.Item.Id)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+resp.Item.Id+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+resp.Item.AccessApiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Checkin successful, verify body")
	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var obj map[string]interface{}
	err = json.Unmarshal(p, &obj)
	require.NoError(t, err)

	require.Eventuallyf(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:9200/.fleet-agents/_doc/"+resp.Item.Id, nil)
		require.NoError(t, err)
		req.SetBasicAuth("elastic", "changeme")
		res, err := cli.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return false
		}
		p, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		var tmp map[string]interface{}
		err = json.Unmarshal(p, &tmp)
		require.NoError(t, err)
		o, ok := tmp["_source"]
		require.Truef(t, ok, "expected to find _source in: %v", tmp)
		obj, ok := o.(map[string]interface{})
		require.Truef(t, ok, "expected _source to be an object, was: %T", o)
		_, ok = obj["audit_unenrolled_reason"]
		_, ok2 := obj["unenrolled_at"]
		return !ok && !ok2
	}, time.Second*20, time.Second, "agent document should not have the audit_unenrolled_reason or unenrolled_at attributes. agent doc: %v", obj)
	cancel()
	srv.waitExit() //nolint:errcheck // test case
}

func TestCheckinOTelColPolicy(t *testing.T) {
	ctx := t.Context()

	idSuffix := uuid.Must(uuid.NewV4()).String()
	componentID := func(id string) string {
		return fmt.Sprintf("%s/%s", id, idSuffix)
	}
	policyData := model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]any{},
		Receivers: map[string]any{
			componentID("somereceiver"): map[string]any{},
		},
		Processors: map[string]any{
			componentID("someprocessor"): map[string]any{},
		},
		Connectors: map[string]any{
			"forward": map[string]any{},
		},
		Exporters: map[string]any{
			"elasticsearch/default": map[string]any{},
		},
		Service: &model.Service{
			Pipelines: map[string]*model.PipelinesItem{
				componentID("metrics"): &model.PipelinesItem{
					Receivers:  []string{componentID("somereceiver")},
					Processors: []string{componentID("someprocessor")},
					Exporters:  []string{"forward"},
				},
				"metrics": &model.PipelinesItem{
					Receivers: []string{"forward"},
					Exporters: []string{"elasticsearch/default"},
				},
			},
		},
	}

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)
	ctx = testlog.SetLogger(t).WithContext(ctx)

	cli := cleanhttp.DefaultClient()
	// enroll an agent
	t.Log("Enroll an agent")
	req, err := http.NewRequestWithContext(ctx, "POST", srv.buildURL("", "enroll"), strings.NewReader(enrollBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+srv.enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Agent enrollment successful")
	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var enrollResponse struct {
		Item struct {
			ID           string `json:"id"`
			AccessApiKey string `json:"access_api_key"`
		} `json:"item"`
	}
	err = json.Unmarshal(p, &enrollResponse)
	require.NoError(t, err)
	agentID := enrollResponse.Item.ID
	apiKey := enrollResponse.Item.AccessApiKey

	// checkin
	t.Logf("Fake a checkin for agent %s", agentID)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.buildURL(agentID, "checkin"), strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Checkin successful, verify body")
	p, err = io.ReadAll(res.Body)
	require.NoError(t, err)

	var checkinResponse struct {
		Actions []struct {
			AgentID string `json:"agent_id"`
			ID      string `json:"id"`
			Data    struct {
				Policy struct {
					Exporters map[string]struct {
						ApiKey string `json:"api_key"`
					} `json:"exporters"`
					Outputs map[string]struct {
						ApiKey string `json:"api_key"`
						Type   string `json:"type"`
					} `json:"outputs"`
				} `json:"policy"`
			} `json:"data"`
		} `json:"actions"`
	}
	err = json.Unmarshal(p, &checkinResponse)
	require.NoError(t, err)

	require.Len(t, checkinResponse.Actions, 1, "expected 1 action")

	action := checkinResponse.Actions[0]
	assert.NotEmpty(t, action.ID)
	assert.Equal(t, agentID, action.AgentID)

	output, found := action.Data.Policy.Outputs["default"]
	require.True(t, found, "default output not found")
	require.Equal(t, "elasticsearch", output.Type)
	require.NotEmpty(t, output.ApiKey)

	exporter, found := action.Data.Policy.Exporters["elasticsearch/default"]
	require.True(t, found, "default exporter not found")
	encodedApiKey := base64.StdEncoding.EncodeToString([]byte(output.ApiKey))

	assert.Equal(t, encodedApiKey, exporter.ApiKey)
}
