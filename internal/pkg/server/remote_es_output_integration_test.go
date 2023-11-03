// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/require"
)

func Checkin(t *testing.T, ctx context.Context, srv *tserver, agentID, key string) {
	str := agentID
	cli := cleanhttp.DefaultClient()
	var obj map[string]interface{}

	t.Logf("Fake a checkin for agent %s", str)
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+str+"/checkin", strings.NewReader(checkinBody))
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
	require.Greater(t, len(actions), 0, "expected at least 1 action")
	action, ok := actions[0].(map[string]interface{})
	require.True(t, ok, "expected action to be an object")
	typeRaw := action["type"]
	require.Equal(t, "POLICY_CHANGE", typeRaw)
	dataRaw := action["data"]
	data := dataRaw.(map[string]interface{})
	policy := data["policy"].(map[string]interface{})
	outputs := policy["outputs"].(map[string]interface{})
	remoteES := outputs["remoteES"].(map[string]interface{})
	oType := remoteES["type"].(string)
	require.Equal(t, "elasticsearch", oType)
	serviceToken := remoteES["service_token"]
	require.Equal(t, nil, serviceToken)
	remoteAPIKey := remoteES["api_key"]
	defaultOutput := outputs["default"].(map[string]interface{})
	defaultAPIKey := defaultOutput["api_key"]
	require.False(t, remoteAPIKey == defaultAPIKey, "expected remote api key to be different than default")

}

func Test_Agent_Remote_ES_Output(t *testing.T) {
	enrollBody := `{
	    "type": "PERMANENT",
	    "shared_id": "",
	    "enrollment_id": "",
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

	t.Log("Create policy with remote ES output")

	var policyRemoteID = "policyRemoteID"
	var policyDataRemoteES = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
			"remoteES": {
				"type": "remote_elasticsearch",
				// TODO start another fleet-server
				"hosts": []string{"localhost:9200"},
				// TODO create remote service token - superuser? manage_service_account
				"service_token": srv.cfg.Output.Elasticsearch.ServiceToken,
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}, "remoteES": {}}`),
		Inputs:            []map[string]interface{}{},
	}

	_, err = dl.CreatePolicy(ctx, srv.bulker, model.Policy{
		PolicyID:           policyRemoteID,
		RevisionIdx:        1,
		DefaultFleetServer: false,
		Data:               &policyDataRemoteES,
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
		Name:     "RemoteES",
		APIKey:   newKey.Key,
		APIKeyID: newKey.ID,
		PolicyID: policyRemoteID,
		Active:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Enroll agent")
	srvCopy := srv
	srvCopy.enrollKey = newKey.Token()
	agentID, key := EnrollAgent(enrollBody, t, ctx, srvCopy)

	// cleanup
	defer func() {
		err2 := srv.bulker.Delete(ctx, dl.FleetAgents, agentID)
		if err2 != nil {
			t.Log("could not clean up agent")
		}
	}()

	Checkin(t, ctx, srvCopy, agentID, key)
}
