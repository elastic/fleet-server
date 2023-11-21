// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/require"
)

func Checkin(t *testing.T, ctx context.Context, srv *tserver, agentID, key string) string {
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
	data, ok := dataRaw.(map[string]interface{})
	require.True(t, ok, "expected data to be map")
	policy, ok := data["policy"].(map[string]interface{})
	require.True(t, ok, "expected policy to be map")
	outputs, ok := policy["outputs"].(map[string]interface{})
	require.True(t, ok, "expected outputs to be map")
	remoteES, ok := outputs["remoteES"].(map[string]interface{})
	require.True(t, ok, "expected remoteES to be map")
	oType, ok := remoteES["type"].(string)
	require.True(t, ok, "expected type to be string")
	require.Equal(t, "elasticsearch", oType)
	serviceToken := remoteES["service_token"]
	require.Equal(t, nil, serviceToken)
	remoteAPIKey, ok := remoteES["api_key"].(string)
	require.True(t, ok, "expected remoteAPIKey to be string")
	defaultOutput, ok := outputs["default"].(map[string]interface{})
	require.True(t, ok, "expected default to be map")
	defaultAPIKey, ok := defaultOutput["api_key"].(string)
	require.True(t, ok, "expected defaultAPIKey to be string")
	require.NotEqual(t, remoteAPIKey, defaultAPIKey, "expected remote api key to be different than default")
	return remoteAPIKey
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
	remoteESHost := "localhost:9201"
	var policyDataRemoteES = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
			"remoteES": {
				"type":          "remote_elasticsearch",
				"hosts":         []string{remoteESHost},
				"service_token": os.Getenv("REMOTE_ELASTICSEARCH_SERVICE_TOKEN"),
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

	remoteAPIKey := Checkin(t, ctx, srvCopy, agentID, key)
	apiKeyID := strings.Split(remoteAPIKey, ":")[0]

	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		requestURL := fmt.Sprintf("http://elastic:changeme@%s/_security/api_key?id=%s", remoteESHost, apiKeyID)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			t.Fatal("error creating request for remote api key")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal("error querying remote api key")
		}

		require.Equal(t, 200, res.StatusCode)

		defer res.Body.Close()
		respString, err := io.ReadAll(res.Body)
		require.NoError(t, err, "did not expect error when parsing api key response")

		require.Contains(t, string(respString), "\"invalidated\":false")
		return nil
	}, ftesting.RetrySleep(1*time.Second))
}
