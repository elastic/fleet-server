// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

//nolint:dupl // don't care about repeating code
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

const (
	serverVersion = "8.0.0"

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
	    "message": ""
	}`
)

type tserver struct {
	cfg       *config.Config
	g         *errgroup.Group
	srv       *Fleet
	enrollKey string
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
	return s.g.Wait()
}

func startTestServer(t *testing.T, ctx context.Context) (*tserver, error) {
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
		Data:               policyData,
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
	srvcfg.Host = "localhost"
	srvcfg.Port = port
	cfg.Inputs[0].Server = *srvcfg
	log.Info().Uint16("port", port).Msg("Test fleet server")

	srv, err := NewFleet(build.Info{Version: serverVersion}, state.NewLog(), false)
	if err != nil {
		return nil, fmt.Errorf("unable to create server: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return srv.Run(ctx, cfg)
	})

	tsrv := &tserver{cfg: cfg, g: g, srv: srv, enrollKey: key.Token()}
	err = tsrv.waitServerUp(ctx, testWaitServerUp)
	if err != nil {
		return nil, fmt.Errorf("unable to start server: %w", err)
	}
	return tsrv, nil
}

func (s *tserver) waitServerUp(ctx context.Context, dur time.Duration) error {
	start := time.Now()
	cli := cleanhttp.DefaultClient()
	for {
		req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+"/api/status", nil)
		if err != nil {
			return err
		}
		res, err := cli.Do(req)
		if err != nil {
			if time.Since(start) > dur {
				return err
			}
		} else {
			defer res.Body.Close()
			return nil
		}

		err = sleep.WithContext(ctx, 100*time.Millisecond)
		if err != nil {
			return err
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

func TestServerUnauthorized(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx)
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
			diff := cmp.Diff(400, res.StatusCode)
			if diff != "" {
				t.Fatal(diff)
			}

			raw, _ := ioutil.ReadAll(res.Body)
			var resp api.HTTPErrResp
			err = json.Unmarshal(raw, &resp)
			if err != nil {
				t.Fatal(err)
			}
			diff = cmp.Diff(400, resp.StatusCode)
			if diff != "" {
				t.Fatal(diff)
			}
			diff = cmp.Diff("BadRequest", resp.Error)
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

			diff := cmp.Diff(400, res.StatusCode)
			if diff != "" {
				t.Fatal(diff)
			}

			raw, _ := ioutil.ReadAll(res.Body)
			var resp api.HTTPErrResp
			err = json.Unmarshal(raw, &resp)
			if err != nil {
				t.Fatal(err)
			}
			diff = cmp.Diff(400, resp.StatusCode)
			if diff != "" {
				t.Fatal(diff)
			}
			diff = cmp.Diff("BadRequest", resp.Error)
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
	tracerDisconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/intake/v2/events" {
			return
		}
		tracerConnected <- struct{}{}
		io.Copy(io.Discard, req.Body) //nolint:errcheck // test case
		tracerDisconnected <- struct{}{}
	}))
	defer server.Close()

	// Start test server
	srv, err := startTestServer(t, ctx)
	require.NoError(t, err)

	newInstrumentationCfg := func(cfg config.Config, instr config.Instrumentation) { //nolint:govet // mutex should not be copied in operation (hopefully)
		cfg.Inputs[0].Server.Instrumentation = instr

		newCfg, err := srv.cfg.Merge(&cfg)
		require.NoError(t, err)

		require.NoError(t, srv.srv.Reload(ctx, newCfg))
	}

	// Enable instrumentation
	newInstrumentationCfg(*srv.cfg, config.Instrumentation{ //nolint:govet // mutex should not be copied in operation (hopefully)
		Enabled: true,
		Hosts:   []string{server.URL},
	})

	stopClient := make(chan struct{})
	cli := cleanhttp.DefaultClient()
	callCheckinFunc := func() {
		var Err error
		defer require.NoError(t, Err)
		for {
			agentID := "1e4954ce-af37-4731-9f4a-407b08e69e42"
			req, _ := http.NewRequestWithContext(ctx, "POST", srv.buildURL(agentID, "checkin"), bytes.NewBuffer([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			res, err := cli.Do(req) //nolint:staticcheck // error check work around
			if res != nil && res.Body != nil {
				res.Body.Close()
			}
			Err = err //nolint:ineffassign,staticcheck // ugly work around for error checking
			select {
			case <-ctx.Done():
				return
			case <-stopClient:
				return
			case <-time.After(time.Second):
			}
		}
	}
	go callCheckinFunc()

	// Verify the APM tracer connects to the mocked APM Server.
	// Errors if the tracer doesn't establish a connection within 5 seconds.
	select {
	case <-tracerConnected:
		stopClient <- struct{}{}
	case <-time.After(5 * time.Second):
		t.Error("did not receive any data from the instrumented fleet-server")
	}

	// Turn instrumentation off
	newInstrumentationCfg(*srv.cfg, config.Instrumentation{ //nolint:govet // mutex should not be copied in operation (hopefully)
		Enabled: false,
		Hosts:   []string{server.URL},
	})

	// Verify the APM Tracer closes the connection to the mocked APM Server.
	// Errors if the hasn't closed the connection after 5 seconds.
	select {
	case <-tracerDisconnected:
	case <-time.After(5 * time.Second):
		t.Error("APM tracer still connected after server restart, bug in the tracing code")
	}

	go callCheckinFunc()

	// Verify the APM Tracer doesn't connect to the mocked APM Server.
	select {
	case <-tracerConnected:
		t.Error("APM Tracer connected to APM Server, bug in the tracing code")
	case <-time.After(5 * time.Second):
	}

	stopClient <- struct{}{}
	close(stopClient)
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
	srv, err := startTestServer(t, ctx)
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

func Test_Agent_Auth_errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx)
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
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
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
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
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
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func Test_Agent_request_errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx)
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
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
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
