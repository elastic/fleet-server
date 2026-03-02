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
	"strings"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/go-elasticsearch/v8"

	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

// createAgentPolicyWithOtelSecrets creates two ES secrets, builds a policy that
// references them across all five OTEL sections, and returns the enrollment token
// for the new policy.  All data-layer setup is done here so callers only need
// to perform the HTTP enroll/checkin flow.
func createAgentPolicyWithOtelSecrets(t *testing.T, ctx context.Context, bulker bulk.Bulk) string {
	t.Helper()

	inlineSecretID := createSecret(t, ctx, bulker, "inline_secret_value")
	inlineSecretRef := fmt.Sprintf("$co.elastic.secret{%s}", inlineSecretID)
	pathSecretID := createSecret(t, ctx, bulker, "path_secret_value")

	policyID := uuid.Must(uuid.NewV4()).String()
	var otelPolicyData = model.PolicyData{
		Outputs: map[string]map[string]any{
			"default": {
				"type": "elasticsearch",
			},
		},
		OutputPermissions: json.RawMessage(`{"default":{}}`),
		Receivers: map[string]any{
			"otlp": map[string]any{
				"auth": inlineSecretRef,
			},
		},
		// Exporter IDs must be "type/outputName"; only "elasticsearch" is supported.
		Exporters: map[string]any{
			"elasticsearch/default": map[string]any{
				"secrets": map[string]any{
					"headers": map[string]any{
						"authorization": map[string]any{"id": pathSecretID},
					},
				},
			},
		},
		Processors: map[string]any{
			"batch": map[string]any{
				"api_key": inlineSecretRef,
			},
		},
		Extensions: map[string]any{
			"basicauth": map[string]any{
				"secrets": map[string]any{
					"password": map[string]any{"id": pathSecretID},
				},
			},
		},
		Connectors: map[string]any{
			"spanmetrics": map[string]any{
				"token": inlineSecretRef,
			},
		},
		SecretReferences: []model.SecretReferencesItems{
			{ID: inlineSecretID},
			{ID: pathSecretID},
		},
	}

	_, err := dl.CreatePolicy(ctx, bulker, model.Policy{
		PolicyID:           policyID,
		RevisionIdx:        1,
		DefaultFleetServer: true,
		Data:               &otelPolicyData,
	})
	if err != nil {
		t.Fatal(err)
	}

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
	}`), map[string]any{
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
		t.Fatal(err)
	}
	return key.Token()
}

func Test_Agent_OtelPolicy_Secrets(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	// Create secrets and policy with OTEL secret references before any agent interaction.
	enrollKey := createAgentPolicyWithOtelSecrets(t, ctx, srv.bulker)

	cli := cleanhttp.DefaultClient()

	// enroll an agent
	t.Log("Enroll an agent")
	req, err := http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/enroll", strings.NewReader(enrollBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+enrollKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	require.NoError(t, err)
	p, _ := io.ReadAll(res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode, "expected 200 OK return code, got %d: %s", res.StatusCode, string(p))
	t.Log("Agent enrollment successful")

	var obj map[string]any
	err = json.Unmarshal(p, &obj)
	require.NoError(t, err)

	item := obj["item"]
	mm, ok := item.(map[string]any)
	require.True(t, ok, "expected attribute item to be an object")
	id := mm["id"]
	agentID, ok := id.(string)
	require.True(t, ok, "expected attribute id to be a string")

	apiKeyVal := mm["access_api_key"]
	apiKey, ok := apiKeyVal.(string)
	require.True(t, ok, "expected attribute access_api_key to be a string")

	// checkin
	t.Logf("Fake a checkin for agent %s", agentID)
	req, err = http.NewRequestWithContext(ctx, "POST", srv.baseURL()+"/api/fleet/agents/"+agentID+"/checkin", strings.NewReader(checkinBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err = cli.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode, "expected checkin status to be 200 OK, got %d: %s", res.StatusCode, string(body))

	t.Log("Checkin successful, verify body")

	var checkinResponse api.CheckinResponse
	err = json.Unmarshal(body, &checkinResponse)
	require.NoError(t, err)

	// expect 1 POLICY_CHANGE action
	assert.Len(t, checkinResponse.Actions, 1)
	assert.Equal(t, api.POLICYCHANGE, checkinResponse.Actions[0].Type)
	actionData, err := checkinResponse.Actions[0].Data.AsActionPolicyChange()
	require.NoError(t, err)

	// Assert receivers.otlp.auth was replaced with inline secret value
	require.Contains(t, actionData.Policy.Receivers, "otlp")
	otlpMap, ok := actionData.Policy.Receivers["otlp"].(map[string]any)
	require.True(t, ok, "expected receivers.otlp to be a map")
	assert.Equal(t, "inline_secret_value", otlpMap["auth"])

	// Assert exporters.elasticsearch/default.headers.authorization was replaced with
	// path secret value and the 'secrets' wrapper key removed.
	// prepareOTelExporters also injects api_key from the prepared output.
	require.Contains(t, actionData.Policy.Exporters, "elasticsearch/default")
	esExporterMap, ok := actionData.Policy.Exporters["elasticsearch/default"].(map[string]any)
	require.True(t, ok, "expected exporters.elasticsearch/default to be a map")
	assert.NotContains(t, esExporterMap, "secrets", "expected 'secrets' key to be removed from exporters.elasticsearch/default")
	require.Contains(t, esExporterMap, "headers")
	headersMap, ok := esExporterMap["headers"].(map[string]any)
	require.True(t, ok, "expected exporters.elasticsearch/default.headers to be a map")
	assert.Equal(t, "path_secret_value", headersMap["authorization"])

	// Assert processors.batch.api_key was replaced with inline secret value
	require.Contains(t, actionData.Policy.Processors, "batch")
	batchMap, ok := actionData.Policy.Processors["batch"].(map[string]any)
	require.True(t, ok, "expected processors.batch to be a map")
	assert.Equal(t, "inline_secret_value", batchMap["api_key"])

	// Assert extensions.basicauth.password was replaced with path secret value
	require.Contains(t, actionData.Policy.Extensions, "basicauth")
	basicauthMap, ok := actionData.Policy.Extensions["basicauth"].(map[string]any)
	require.True(t, ok, "expected extensions.basicauth to be a map")
	assert.NotContains(t, basicauthMap, "secrets", "expected 'secrets' key to be removed from extensions.basicauth")
	assert.Equal(t, "path_secret_value", basicauthMap["password"])

	// Assert connectors.spanmetrics.token was replaced with inline secret value
	require.Contains(t, actionData.Policy.Connectors, "spanmetrics")
	spanmetricsMap, ok := actionData.Policy.Connectors["spanmetrics"].(map[string]any)
	require.True(t, ok, "expected connectors.spanmetrics to be a map")
	assert.Equal(t, "inline_secret_value", spanmetricsMap["token"])

	// Assert secret_paths contains the expected OTEL keys
	assert.ElementsMatch(t,
		[]string{
			"receivers.otlp.auth",
			"exporters.elasticsearch/default.headers.authorization",
			"processors.batch.api_key",
			"extensions.basicauth.password",
			"connectors.spanmetrics.token",
		},
		actionData.Policy.SecretPaths,
	)

}
