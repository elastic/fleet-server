// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/require"
)

func AgentCheckin(t *testing.T, ctx context.Context, srv *tserver, agentID, key string) string {
	cli := cleanhttp.DefaultClient()
	var obj map[string]interface{}

	t.Logf("Fake a checkin for agent %s", agentID)
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+key)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Checkin successful, verify body")
	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	err = json.Unmarshal(p, &obj)
	require.NoError(t, err)

	actionsRaw, ok := obj["actions"]
	require.True(t, ok, "expected actions is missing")
	actions, ok := actionsRaw.([]interface{})
	require.True(t, ok, "expected actions to be an array")
	require.Equal(t, len(actions), 1, "expected 1 action")
	action, ok := actions[0].(map[string]interface{})
	require.True(t, ok, "expected action to be an object")

	aIDRaw, ok := action["id"]
	require.True(t, ok, "expected action id attribute missing")
	actionID, ok := aIDRaw.(string)
	require.True(t, ok, "expected action id to be string")

	return actionID
}

func AgentAck(t *testing.T, ctx context.Context, srv *tserver, actionID, agentID, key string) {
	t.Logf("Fake an ack for action %s for agent %s", actionID, agentID)
	body := fmt.Sprintf(`{
	    "events": [{
		"action_id": "%s",
		"agent_id": "%s",
		"message": "test-message",
		"type": "ACTION_RESULT",
		"subtype": "ACKNOWLEDGED"
	    }]
	}`, actionID, agentID)
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/acks", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+key)
	req.Header.Set("Content-Type", "application/json")
	cli := cleanhttp.DefaultClient()
	res, err := cli.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Ack successful, verify body")
}

type GetAgentResponse struct {
	Agent model.Agent `json:"_source"`
}

func AssertAgentDocContainNamespace(t *testing.T, ctx context.Context, srv *tserver, agentID string, namespace string) {
	res, err := srv.bulker.Client().Get(".fleet-agents", agentID)
	require.NoError(t, err)

	defer res.Body.Close()
	var getAgentRes GetAgentResponse
	err = json.NewDecoder(res.Body).Decode(&getAgentRes)
	require.NoError(t, err)

	require.EqualValues(t, getAgentRes.Agent.Namespaces, []string{namespace})
}

func CreateActionDocument(t *testing.T, ctx context.Context, srv *tserver, action model.Action) {
	body, err := json.Marshal(action)
	require.NoError(t, err)
	_, err = srv.bulker.Client().Index(".fleet-actions", bytes.NewReader(body))
	require.NoError(t, err)
}

type GetActionResults struct {
	Hits struct {
		Hits []struct {
			Result model.ActionResult `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

func CheckActionResultsNamespace(t *testing.T, ctx context.Context, srv *tserver, actionID string, namespace string) {
	queryTmpl := `{
		"query": {
			"bool" : {
				"must" : {
					"terms": {
						"action_id": [ "{{.}}" ]
					}
				}
			}
		}
	}`
	queryBuff := bytes.Buffer{}
	tmpl, err := template.New("").Parse(queryTmpl)
	require.NoError(t, err)
	err = tmpl.Execute(&queryBuff, actionID)
	require.NoError(t, err)

	client := srv.bulker.Client()

	res, err := client.Search(
		client.Search.WithIndex(".fleet-actions-results"),
		client.Search.WithBody(strings.NewReader(queryBuff.String())),
	)
	defer res.Body.Close()
	require.NoError(t, err)

	var getActionResultsRes GetActionResults
	err = json.NewDecoder(res.Body).Decode(&getActionResultsRes)
	require.NoError(t, err)

	require.Len(t, getActionResultsRes.Hits.Hits, 1)
	require.EqualValues(t, getActionResultsRes.Hits.Hits[0].Result.Namespaces, []string{namespace})
}

func Test_Agent_Namespace_test1(t *testing.T) {
	testNamespace := "test1"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	t.Log("Create policy with namespace test1")
	var policyRemoteID = uuid.Must(uuid.NewV4()).String()
	var policyDataNamespaceTest = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {} }`),
		Inputs:            []map[string]interface{}{},
		Agent:             map[string]interface{}{"monitoring": {"use_output": "default"}},
	}

	_, err = dl.CreatePolicy(ctx, srv.bulker, model.Policy{
		PolicyID:           policyRemoteID,
		Namespaces:         []string{testNamespace},
		RevisionIdx:        1,
		DefaultFleetServer: false,
		Data:               &policyDataNamespaceTest,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Create API key and enrollment key for new policy")
	newKey, err := apikey.Create(ctx, srv.bulker.Client(), "default", "", "true", []byte(`{
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
		"policy_id":  policyRemoteID,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = dl.CreateEnrollmentAPIKey(ctx, srv.bulker, model.EnrollmentAPIKey{
		Name:       "TestNamespace1",
		Namespaces: []string{testNamespace},
		APIKey:     newKey.Key,
		APIKeyID:   newKey.ID,
		PolicyID:   policyRemoteID,
		Active:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Enroll agent")
	srvCopy := srv
	srvCopy.enrollKey = newKey.Token()
	resp := EnrollAgent(t, ctx, srvCopy, enrollBody)

	AssertAgentDocContainNamespace(t, ctx, srv, resp.Item.Id, testNamespace)
	// cleanup
	defer func() {
		err = srv.bulker.Delete(ctx, dl.FleetAgents, resp.Item.Id)
		if err != nil {
			t.Log("could not clean up agent")
		}
	}()

	actionID := AgentCheckin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey)
	AgentAck(t, ctx, srvCopy, actionID, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Create SETTINGS Action")
	newActionID, _ := uuid.NewV4()
	var actionData = model.Action{
		Agents:     []string{resp.Item.Id},
		Expiration: time.Now().Add(time.Hour * 2000).Format(time.RFC3339),
		ActionID:   newActionID.String(),
		Namespaces: []string{"test1"},
		Type:       "SETTINGS",
		Data:       []byte("{\"log_level\": \"debug\"}"),
	}

	CreateActionDocument(t, ctx, srv, actionData)

	t.Log("Checkin so that agent gets the SETTINGS action")
	actionID = AgentCheckin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Ack so that fleet create the action results")
	AgentAck(t, ctx, srvCopy, actionID, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Check action results has the correct namespace")
	CheckActionResultsNamespace(t, ctx, srv, actionID, "test1")
}
