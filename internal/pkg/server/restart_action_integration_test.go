// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package server

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// Test_Agent_Restart_Action verifies the end-to-end RESTART action flow through
// fleet-server: a RESTART action stored in .fleet-actions is delivered to the
// agent on checkin (with the correct type and no data) and its acknowledgement
// is accepted. It follows the same pattern as Test_Agent_Namespace_test1.
func Test_Agent_Restart_Action(t *testing.T) {
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

	t.Log("Create RESTART action")
	restartActionID := uuid.Must(uuid.NewV4()).String()
	CreateActionDocument(t, ctx, srv, model.Action{
		Agents:     []string{resp.Item.Id},
		Expiration: time.Now().Add(2000 * time.Hour).Format(time.RFC3339),
		ActionID:   restartActionID,
		Type:       string(api.RESTART),
	})

	t.Log("Checkin so that the agent receives the RESTART action")
	// Checkin asserts the delivered action's type equals RESTART and returns its id.
	_, gotID := Checkin(t, ctx, srv, resp.Item.Id, resp.Item.AccessApiKey, false, string(api.RESTART))
	require.Equal(t, restartActionID, gotID, "expected to receive the created RESTART action")

	t.Log("Ack the RESTART action so fleet-server records the result")
	AgentAck(t, ctx, srv, gotID, resp.Item.Id, resp.Item.AccessApiKey)
}
