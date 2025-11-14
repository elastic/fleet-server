// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/require"
)

const (
	remoteESHost = "localhost:9201"
	remoteESUrl  = "https://localhost:9201"
)

func Checkin(t *testing.T, ctx context.Context, srv *tserver, agentID, key string, shouldHaveRemoteES bool, actionType string) (string, string) {
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

	typeRaw := action["type"]
	require.Equal(t, actionType, typeRaw)
	if actionType != "POLICY_CHANGE" {
		return "", actionID
	}
	dataRaw := action["data"]
	data, ok := dataRaw.(map[string]interface{})
	require.True(t, ok, "expected data to be map")
	policy, ok := data["policy"].(map[string]interface{})
	require.True(t, ok, "expected policy to be map")
	outputs, ok := policy["outputs"].(map[string]interface{})
	require.True(t, ok, "expected outputs to be map")
	var remoteAPIKey string
	if shouldHaveRemoteES {
		remoteES, ok := outputs["remoteES"].(map[string]interface{})
		require.True(t, ok, "expected remoteES to be map")
		oType, ok := remoteES["type"].(string)
		require.True(t, ok, "expected type to be string")
		require.Equal(t, "elasticsearch", oType)
		serviceToken := remoteES["service_token"]
		require.Equal(t, nil, serviceToken)
		remoteAPIKey, ok = remoteES["api_key"].(string)
		require.True(t, ok, "expected remoteAPIKey to be string")
	}
	defaultOutput, ok := outputs["default"].(map[string]interface{})
	require.True(t, ok, "expected default to be map")
	defaultAPIKey, ok := defaultOutput["api_key"].(string)
	require.True(t, ok, "expected defaultAPIKey to be string")
	require.NotEqual(t, remoteAPIKey, defaultAPIKey, "expected remote api key to be different than default")

	return remoteAPIKey, actionID
}

func getRemoteElasticsearchCa(t *testing.T) string {
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(os.Getenv("REMOTE_ELASTICSEARCH_CA_CRT_BASE64"), " ", ""))
	require.NoError(t, err)

	return string(data)
}

func Ack(t *testing.T, ctx context.Context, srv *tserver, actionID, agentID, key string) {
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

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Log("Ack successful, verify body")
	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var ackObj map[string]interface{}
	err = json.Unmarshal(p, &ackObj)
	require.NoError(t, err)

	// NOTE the checkin response will only have the errors attribute if it's set to true in the response.
	// When decoding to a (typed) struct, the default will implicitly be false if it's missing
	_, ok := ackObj["errors"]
	require.Falsef(t, ok, "expected response to have no errors attribute, errors are present: %+v", ackObj)
}

func Test_Agent_Remote_ES_Output(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	t.Log("Create policy with remote ES output")

	var policyRemoteID = uuid.Must(uuid.NewV4()).String()
	var policyDataRemoteES = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
			"remoteES": {
				"type":                        "remote_elasticsearch",
				"hosts":                       []string{remoteESUrl},
				"service_token":               os.Getenv("REMOTE_ELASTICSEARCH_SERVICE_TOKEN"),
				"ssl.enabled":                 true,
				"ssl.certificate_authorities": []string{getRemoteElasticsearchCa(t)},
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}, "remoteES": {}}`),
		Inputs:            []map[string]interface{}{},
		Agent:             map[string]interface{}{"monitoring": {"use_output": "remoteES"}},
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
	resp := EnrollAgent(t, ctx, srvCopy, enrollBody)

	// cleanup
	defer func() {
		err = srv.bulker.Delete(ctx, dl.FleetAgents, resp.Item.Id)
		if err != nil {
			t.Log("could not clean up agent")
		}
	}()

	remoteAPIKey, actionID := Checkin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey, true, "POLICY_CHANGE")
	apiKeyID := strings.Split(remoteAPIKey, ":")[0]

	verifyRemoteAPIKey(t, ctx, apiKeyID, false)

	Ack(t, ctx, srvCopy, actionID, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Update policy to remove remote ES output")

	var policyData = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]interface{}{},
	}

	_, err = dl.CreatePolicy(ctx, srv.bulker, model.Policy{
		PolicyID:           policyRemoteID,
		RevisionIdx:        2,
		DefaultFleetServer: false,
		Data:               &policyData,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Checkin so that agent gets new policy revision")
	_, actionID = Checkin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey, false, "POLICY_CHANGE")

	t.Log("Ack so that fleet triggers remote api key invalidate")
	Ack(t, ctx, srvCopy, actionID, resp.Item.Id, resp.Item.AccessApiKey)

	verifyRemoteAPIKey(t, ctx, apiKeyID, true)

}

func verifyRemoteAPIKey(t *testing.T, ctx context.Context, apiKeyID string, invalidated bool) {
	// need to wait a bit before querying the api key
	time.Sleep(time.Second)

	requestURL := fmt.Sprintf("https://elastic:changeme@%s/_security/api_key?id=%s", remoteESHost, apiKeyID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	// Skip SSL verify as ES use self-signed certificate
	tr := &http.Transport{
		// #nosec G402
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	if err != nil {
		t.Fatal("error creating request for remote api key")
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("error querying remote api key")
	}

	require.Equal(t, 200, res.StatusCode)

	defer res.Body.Close()
	respString, err := io.ReadAll(res.Body)
	require.NoError(t, err, "did not expect error when parsing api key response")

	require.Contains(t, string(respString), fmt.Sprintf("\"invalidated\":%t", invalidated))
}

func Test_Agent_Remote_ES_Output_ForceUnenroll(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	t.Log("Create policy with remote ES output")

	var policyRemoteID = uuid.Must(uuid.NewV4()).String()
	var policyDataRemoteES = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
			"remoteES": {
				"type":                        "remote_elasticsearch",
				"hosts":                       []string{remoteESUrl},
				"service_token":               os.Getenv("REMOTE_ELASTICSEARCH_SERVICE_TOKEN"),
				"ssl.enabled":                 true,
				"ssl.certificate_authorities": []string{getRemoteElasticsearchCa(t)},
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}, "remoteES": {}}`),
		Inputs:            []map[string]interface{}{},
		Agent:             map[string]interface{}{"monitoring": {"use_output": "remoteES"}},
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
	resp := EnrollAgent(t, ctx, srvCopy, enrollBody)

	// cleanup
	defer func() {
		err = srv.bulker.Delete(ctx, dl.FleetAgents, resp.Item.Id)
		if err != nil {
			t.Log("could not clean up agent")
		}
	}()

	remoteAPIKey, actionID := Checkin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey, true, "POLICY_CHANGE")
	apiKeyID := strings.Split(remoteAPIKey, ":")[0]

	verifyRemoteAPIKey(t, ctx, apiKeyID, false)

	Ack(t, ctx, srvCopy, actionID, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Force Unenroll agent - set inactive")

	doc := bulk.UpdateFields{
		"active": false,
	}
	body, err := doc.Marshal()
	require.NoError(t, err)
	err = srv.bulker.Update(ctx, dl.FleetAgents, resp.Item.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3))
	require.NoError(t, err)

	t.Log("Checkin so that invalidate logic runs")

	cli := cleanhttp.DefaultClient()

	t.Logf("Fake a checkin for agent %s", resp.Item.Id)
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+resp.Item.Id+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+resp.Item.AccessApiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	t.Log("Verify that remote API key is invalidated")
	verifyRemoteAPIKey(t, ctx, apiKeyID, true)

}

func Test_Agent_Remote_ES_Output_Unenroll(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start test server
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	t.Log("Create policy with remote ES output")

	var policyRemoteID = uuid.Must(uuid.NewV4()).String()
	var policyDataRemoteES = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
			"remoteES": {
				"type":                        "remote_elasticsearch",
				"hosts":                       []string{remoteESUrl},
				"service_token":               os.Getenv("REMOTE_ELASTICSEARCH_SERVICE_TOKEN"),
				"ssl.enabled":                 true,
				"ssl.certificate_authorities": []string{getRemoteElasticsearchCa(t)},
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}, "remoteES": {}}`),
		Inputs:            []map[string]interface{}{},
		Agent:             map[string]interface{}{"monitoring": {"use_output": "remoteES"}},
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
	resp := EnrollAgent(t, ctx, srvCopy, enrollBody)

	// cleanup
	defer func() {
		err = srv.bulker.Delete(ctx, dl.FleetAgents, resp.Item.Id)
		if err != nil {
			t.Log("could not clean up agent")
		}
	}()

	remoteAPIKey, actionID := Checkin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey, true, "POLICY_CHANGE")
	apiKeyID := strings.Split(remoteAPIKey, ":")[0]

	verifyRemoteAPIKey(t, ctx, apiKeyID, false)

	Ack(t, ctx, srvCopy, actionID, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Unenroll agent")

	doc := fmt.Sprintf(`{
		"action_id": "unenroll_action1",
		"agents": ["%s"],
		"@timestamp": "2023-12-11T13:00:00.000Z",
		"expiration": "2099-01-10T13:14:36.565Z",
		"type": "UNENROLL"
	}`, resp.Item.Id)
	client := srv.bulker.Client()
	res, err := client.Index(".fleet-actions", strings.NewReader(doc))
	require.NoError(t, err)
	require.Equal(t, 201, res.StatusCode)

	t.Log("Checkin so that agent gets unenroll action")
	_, actionID = Checkin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey, false, "UNENROLL")
	t.Log(actionID)

	t.Log("Ack so that fleet triggers remote api key invalidate")
	Ack(t, ctx, srvCopy, actionID, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Verify that remote API key is invalidated")
	verifyRemoteAPIKey(t, ctx, apiKeyID, true)

}
