// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// Test_Agent_Uninstall_Action verifies the Fleet Server side of the UNINSTALL
// action. UNINSTALL is only allowed after the agent has been unenrolled: the
// UNENROLL ack moves the agent into the pending-uninstall state (credentials
// kept, agent still active) so it can still receive the follow-up UNINSTALL;
// the UNINSTALL ack then invalidates the API keys and marks the agent inactive.
// It follows the same pattern as Test_Agent_Namespace_test1.
func Test_Agent_Uninstall_Action(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	t.Log("Enroll agent")
	resp := EnrollAgent(t, ctx, srv, enrollBody)
	defer func() {
		if err := srv.bulker.Delete(ctx, dl.FleetAgents, resp.Item.Id); err != nil {
			t.Log("could not clean up agent")
		}
	}()

	// Consume the initial POLICY_CHANGE action produced on the first checkin.
	initialActionID := AgentCheckin(t, ctx, srv, resp.Item.Id, resp.Item.AccessApiKey)
	AgentAck(t, ctx, srv, initialActionID, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Create UNENROLL action (required before UNINSTALL is allowed)")
	unenrollActionID := uuid.Must(uuid.NewV4()).String()
	CreateActionDocument(t, ctx, srv, model.Action{
		Agents:   []string{resp.Item.Id},
		ActionID: unenrollActionID,
		Type:     string(api.UNENROLL),
	})

	t.Log("Checkin so that the agent receives the UNENROLL action")
	_, gotUnenrollID := Checkin(t, ctx, srv, resp.Item.Id, resp.Item.AccessApiKey, false, string(api.UNENROLL))
	require.Equal(t, unenrollActionID, gotUnenrollID, "expected to receive the created UNENROLL action")

	t.Log("Ack the UNENROLL action; the agent keeps its credentials and stays active (pending uninstall)")
	AgentAck(t, ctx, srv, gotUnenrollID, resp.Item.Id, resp.Item.AccessApiKey)
	AssertAgentPendingUninstall(t, ctx, srv, resp.Item.Id)

	t.Log("Create UNINSTALL action")
	uninstallActionID := uuid.Must(uuid.NewV4()).String()
	CreateActionDocument(t, ctx, srv, model.Action{
		Agents:     []string{resp.Item.Id},
		StartTime:  time.Now().Add(30 * time.Minute).Format(time.RFC3339),
		Expiration: time.Now().Add(2000 * time.Hour).Format(time.RFC3339),
		ActionID:   uninstallActionID,
		Type:       string(api.UNINSTALL),
		Data:       []byte(`{}`),
	})

	t.Log("Checkin so that the unenrolled agent receives the UNINSTALL action")
	// Checkin asserts the delivered action's type equals UNINSTALL and returns its id.
	_, gotID := Checkin(t, ctx, srv, resp.Item.Id, resp.Item.AccessApiKey, false, string(api.UNINSTALL))
	require.Equal(t, uninstallActionID, gotID, "expected to receive the created UNINSTALL action")

	t.Log("Ack the UNINSTALL action; Fleet Server invalidates the API keys and marks the agent inactive")
	AgentAck(t, ctx, srv, gotID, resp.Item.Id, resp.Item.AccessApiKey)

	t.Log("Verify the agent is marked inactive after the UNINSTALL ack")
	AssertAgentInactive(t, ctx, srv, resp.Item.Id)
}

// AssertAgentPendingUninstall reads the agent document and asserts it is in the
// pending-uninstall state after an UNENROLL ack: still active with credentials
// kept (so it can receive the UNINSTALL) and uninstall_pending set.
func AssertAgentPendingUninstall(t *testing.T, ctx context.Context, srv *tserver, agentID string) {
	t.Helper()

	res, err := srv.bulker.Client().Get(".fleet-agents", agentID)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Falsef(t, res.IsError(), "expected agent document %q to exist, got status %s", agentID, res.Status())

	var getAgentRes GetAgentResponse
	require.NoError(t, json.NewDecoder(res.Body).Decode(&getAgentRes))
	require.True(t, getAgentRes.Agent.Active, "expected agent to remain active (credentials kept) after UNENROLL")
	require.True(t, getAgentRes.Agent.UninstallPending, "expected agent to be marked pending uninstall after UNENROLL")
}

// AssertAgentInactive reads the agent document and asserts it has been marked
// inactive (active: false), which is set by the API key invalidation path.
func AssertAgentInactive(t *testing.T, ctx context.Context, srv *tserver, agentID string) {
	t.Helper()

	res, err := srv.bulker.Client().Get(".fleet-agents", agentID)
	require.NoError(t, err)
	defer res.Body.Close()

	// A missing document returns 404 with a nil Go error; without this check the
	// decode below would leave Agent.Active at its false zero value and the test
	// would pass even though the agent doc does not exist. Requiring a successful
	// (200) response ensures we are asserting on the real, existing agent document.
	require.Falsef(t, res.IsError(), "expected agent document %q to exist, got status %s", agentID, res.Status())

	var getAgentRes GetAgentResponse
	require.NoError(t, json.NewDecoder(res.Body).Decode(&getAgentRes))
	require.False(t, getAgentRes.Agent.Active, "expected agent to be inactive after UNINSTALL ack")
}
