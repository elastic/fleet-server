// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/go-elasticsearch/v8"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/secret"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)


// Test_Agent_OTLP_Output verifies the full API-key lifecycle for a managed OTLP output:
//
//  1. Agent enrolls under a policy with a managed OTLP output (output_permissions present).
//  2. On first checkin the server mints a scoped ES API key and stores it as a secret ref on the agent doc.
//  3. The agent acks the policy-change action.
//  4. The policy is updated to remove the OTLP output.
//  5. On the next checkin retireRemovedOutput writes a retirement record onto the surviving default
//     output, populating its ToRetireAPIKeyIds with the OTLP key's ID, output name, and secret ID.
//  6. The agent acks that action; handleAck calls invalidateAPIKeys, which cannot resolve a remote
//     bulker for an OTLP output (no service_token) and falls back to the primary cluster — the
//     headline fix in this PR.  Without that fallback the VerifyAPIKeyInvalidated assertion at the
//     end of this test fails.
//  7. deleteRetiredSecrets then removes the OTLP key's .fleet-secrets document.
func Test_Agent_OTLP_Output(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	// Start a fleet server using the default bootstrap policy.
	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	const otlpOutputName = "myOTLP"

	// Build a separate policy (not the fleet-server bootstrap policy) with a managed OTLP output.
	policyID := uuid.Must(uuid.NewV4()).String()
	policyDataWithOTLP := model.PolicyData{
		Outputs: map[string]map[string]any{
			"default":      {"type": "elasticsearch"},
			otlpOutputName: {"type": "otlp"},
		},
		// output_permissions for myOTLP gives it the _managed_otlp_apm role.
		OutputPermissions: json.RawMessage(`{
			"default": {},
			"myOTLP": {
				"_managed_otlp_apm": {
					"applications": [{"application":"apm","privileges":["event:write"],"resources":["*"]}]
				}
			}
		}`),
		Exporters: map[string]any{
			"otlp/" + otlpOutputName: map[string]any{"endpoint": "https://otlp.example:4317"},
		},
		Inputs: []map[string]any{},
	}

	_, err = dl.CreatePolicy(ctx, srv.bulker, model.Policy{
		PolicyID:           policyID,
		RevisionIdx:        1,
		DefaultFleetServer: false,
		Data:               &policyDataWithOTLP,
	})
	require.NoError(t, err)

	// Create an enrollment API key scoped to the OTLP test policy.
	esCfg := elasticsearch.Config{Username: "elastic", Password: "changeme"}
	esClient, err := elasticsearch.NewClient(esCfg)
	require.NoError(t, err)
	enrollKey, err := apikey.Create(ctx, esClient, "default", "", "true", []byte(`{
		"fleet-apikey-enroll": {
			"cluster": [],
			"index": [],
			"applications": [{"application": "fleet", "privileges": ["no-privileges"], "resources": ["*"]}]
		}
	}`), map[string]any{
		"managed_by": "fleet",
		"managed":    true,
		"type":       "enroll",
		"policy_id":  policyID,
	})
	require.NoError(t, err)

	_, err = dl.CreateEnrollmentAPIKey(ctx, srv.bulker, model.EnrollmentAPIKey{
		Name:     "OTLP-test",
		APIKey:   enrollKey.Key,
		APIKeyID: enrollKey.ID,
		PolicyID: policyID,
		Active:   true,
	})
	require.NoError(t, err)

	// Override enrollment key so EnrollAgent uses the OTLP test policy.
	// Assigning through srvCopy modifies the shared tserver struct (both point to the same value).
	srvCopy := srv
	srvCopy.enrollKey = enrollKey.Token()

	resp := EnrollAgent(t, ctx, srvCopy, enrollBody)
	defer func() {
		if err := srv.bulker.Delete(ctx, dl.FleetAgents, resp.Item.Id); err != nil {
			t.Log("could not clean up test agent")
		}
	}()

	// Checkin 1: agent receives the rev-1 POLICY_CHANGE; the server mints a scoped OTLP API key.
	_, actionID1 := Checkin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey, false, "POLICY_CHANGE")

	// Retrieve the minted OTLP key ID and secret reference from the agent doc.
	var otlpKeyID, otlpSecretID string
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		agent, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, resp.Item.Id)
		if err != nil {
			return err
		}
		otlpOut, ok := agent.Outputs[otlpOutputName]
		if !ok {
			return fmt.Errorf("output %q not found on agent doc after checkin", otlpOutputName)
		}
		if otlpOut.APIKeyID == "" {
			return fmt.Errorf("output %q has no APIKeyID on agent doc", otlpOutputName)
		}
		secretID, ok := secret.ParseSecretReference(otlpOut.APIKey)
		if !ok {
			return fmt.Errorf("output %q: api_key %q is not a secret reference", otlpOutputName, otlpOut.APIKey)
		}
		otlpKeyID = otlpOut.APIKeyID
		otlpSecretID = secretID
		return nil
	}, ftesting.RetrySleep(time.Second))

	// The key must be live before the output is removed.
	localESURL := ftesting.LocalESURL()
	ftesting.VerifyAPIKeyInvalidated(t, ctx, localESURL, otlpKeyID, false)

	// Ack the first policy-change action.
	Ack(t, ctx, srvCopy, actionID1, resp.Item.Id, resp.Item.AccessApiKey)

	// Rev-2 policy removes the OTLP output, keeping only the default ES output.
	policyDataWithoutOTLP := model.PolicyData{
		Outputs: map[string]map[string]any{
			"default": {"type": "elasticsearch"},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]any{},
	}
	_, err = dl.CreatePolicy(ctx, srv.bulker, model.Policy{
		PolicyID:           policyID,
		RevisionIdx:        2,
		DefaultFleetServer: false,
		Data:               &policyDataWithoutOTLP,
	})
	require.NoError(t, err)

	// Checkin 2: the server processes the new policy; retireRemovedOutput appends the OTLP key's
	// retirement record to the default output's ToRetireAPIKeyIds.
	_, actionID2 := Checkin(t, ctx, srvCopy, resp.Item.Id, resp.Item.AccessApiKey, false, "POLICY_CHANGE")

	// Verify the retirement record is persisted on the default output.
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		got, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, resp.Item.Id)
		if err != nil {
			return err
		}
		defaultOut, ok := got.Outputs["default"]
		if !ok {
			return fmt.Errorf("default output not found on agent doc")
		}
		if len(defaultOut.ToRetireAPIKeyIds) == 0 {
			return fmt.Errorf("expected ToRetireAPIKeyIds to be populated after %s removal", otlpOutputName)
		}
		return nil
	}, ftesting.RetrySleep(time.Second))

	got, err := dl.FindAgent(ctx, srv.bulker, dl.QueryAgentByID, dl.FieldID, resp.Item.Id)
	require.NoError(t, err)

	defaultOut, ok := got.Outputs["default"]
	require.True(t, ok, "default output must be present on agent doc")
	require.Len(t, defaultOut.ToRetireAPIKeyIds, 1, "exactly one retirement record expected")
	assert.Equal(t, otlpKeyID, defaultOut.ToRetireAPIKeyIds[0].ID, "retired key ID")
	assert.Equal(t, otlpOutputName, defaultOut.ToRetireAPIKeyIds[0].Output, "retired key output name")
	assert.Equal(t, otlpSecretID, defaultOut.ToRetireAPIKeyIds[0].SecretID, "retired key secret ID")
	assert.NotContains(t, got.Outputs, otlpOutputName, "myOTLP entry must be removed from agent doc")

	// Ack 2: invalidateAPIKeys processes the retirement record.  For the myOTLP output, GetBulker
	// returns nil (no remote ES bulker), CreateAndGetBulker fails (OTLP has no service_token), and
	// the primary-cluster fallback introduced in this PR routes the invalidation to local ES.
	//
	// Without the fallback (handleAck.go:769-771) this assertion fails.
	Ack(t, ctx, srvCopy, actionID2, resp.Item.Id, resp.Item.AccessApiKey)

	ftesting.VerifyAPIKeyInvalidated(t, ctx, localESURL, otlpKeyID, true)

	// deleteRetiredSecrets must have removed the .fleet-secrets document.
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		resolved, err := srv.bulker.ReadSecrets(ctx, []string{otlpSecretID})
		if err != nil {
			return err
		}
		if resolved[otlpSecretID] != "" {
			return fmt.Errorf("secret %s still present after ack; want deleted", otlpSecretID)
		}
		return nil
	}, ftesting.RetrySleep(time.Second))
}
