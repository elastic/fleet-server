// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// Test_Upgrade_Results verifies how the UPGRADE action result is recorded (elastic/fleet-server#8274):
// the result comes from the check-in upgrade_details once the outcome is known, and an UPGRADE ack
// whose action matches the stored upgrade_details writes nothing.
func Test_Upgrade_Results(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	srv, err := startTestServer(t, ctx, policyData)
	require.NoError(t, err)

	t.Run("failed upgrade is recorded with the error", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.checkin(api.UpgradeDetailsStateUPGDOWNLOADING, nil)
		require.Empty(t, u.results(), "no result while the upgrade is in progress")

		u.checkin(api.UpgradeDetailsStateUPGFAILED, map[string]any{"failed_state": "UPG_DOWNLOADING", "error_msg": "download failed"})
		res := u.waitResults()
		require.Equal(t, "download failed", res[0].Error)

		agent := u.agent()
		require.Empty(t, agent.UpgradeStartedAt, "upgrade_started_at should be cleared so the agent no longer shows as updating")
		require.NotNil(t, agent.UpgradeDetails)
		require.Equal(t, "UPG_FAILED", agent.UpgradeDetails.State)

		// The agent keeps reporting the terminal state on each check-in; no second result is created.
		u.checkin(api.UpgradeDetailsStateUPGFAILED, map[string]any{"failed_state": "UPG_DOWNLOADING", "error_msg": "download failed"})
		require.Len(t, u.results(), 1)
	})

	t.Run("failed download that can still be retried is not recorded", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		retryUntil := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		u.checkin(api.UpgradeDetailsStateUPGFAILED, map[string]any{"failed_state": "UPG_DOWNLOADING", "error_msg": "copy failed", "retry_until": retryUntil})
		require.Empty(t, u.results(), "no result while the download can still be retried")
		require.NotEmpty(t, u.agent().UpgradeStartedAt, "agent stays updating while the download can be retried")

		// The retry succeeded, the agent proceeds and the upgrade completes: a single success.
		u.checkin(api.UpgradeDetailsStateUPGDOWNLOADING, nil)
		u.checkin(api.UpgradeDetailsStateUPGWATCHING, nil)
		u.ack("")
		require.Empty(t, u.results())
		u.checkinNoDetails()
		res := u.waitResults()
		require.Empty(t, res[0].Error)
	})

	t.Run("failed download is recorded once retry_until has passed", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		retryUntil := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		u.checkin(api.UpgradeDetailsStateUPGFAILED, map[string]any{"failed_state": "UPG_DOWNLOADING", "error_msg": "failed to get upgrade artifact", "retry_until": retryUntil})
		res := u.waitResults()
		require.Equal(t, "failed to get upgrade artifact", res[0].Error)
		require.Empty(t, u.agent().UpgradeStartedAt)
	})

	t.Run("failure after the download is recorded immediately", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.checkin(api.UpgradeDetailsStateUPGFAILED, map[string]any{"failed_state": "UPG_EXTRACTING", "error_msg": "extract failed"})
		res := u.waitResults()
		require.Equal(t, "extract failed", res[0].Error)
	})

	t.Run("canceled scheduled upgrade records no result", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.checkin(api.UpgradeDetailsStateUPGSCHEDULED, map[string]any{"scheduled_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		u.checkinNoDetails() // the agent dropped the queued upgrade after a cancel action
		require.Empty(t, u.results(), "an upgrade that never ran must not be recorded as a success")
		require.Nil(t, u.agent().UpgradeDetails)
	})

	t.Run("rolled back upgrade is recorded with the reason", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.checkin(api.UpgradeDetailsStateUPGWATCHING, nil)
		u.ack("")
		require.Empty(t, u.results(), "the ack must not record a success while the upgrade is being watched")

		u.checkin(api.UpgradeDetailsStateUPGROLLBACK, map[string]any{"reason": "watch failed"})
		res := u.waitResults()
		require.Equal(t, "upgrade rolled back: watch failed", res[0].Error)
		require.Empty(t, u.agent().UpgradeStartedAt)

		// The agent reports UPG_ROLLBACK on every check-in while its marker exists.
		u.checkin(api.UpgradeDetailsStateUPGROLLBACK, map[string]any{"reason": "watch failed"})
		require.Len(t, u.results(), 1)
	})

	t.Run("requested rollback is recorded as a success", func(t *testing.T) {
		u := newUpgradeTestWithData(t, ctx, srv, `{"version":"9.3.0","rollback":true}`)

		u.checkin(api.UpgradeDetailsStateUPGROLLBACK, map[string]any{"reason": "manual rollback requested to version 9.3.0"})
		res := u.waitResults()
		require.Empty(t, res[0].Error, "UPG_ROLLBACK is the successful outcome of a rollback action")
		require.Empty(t, u.agent().UpgradeStartedAt)
	})

	t.Run("failure whose result could not be created is recorded when the details are omitted", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		// upgrade_started_at is still set: the result create failed when UPG_FAILED was reported.
		u.storeUpgradeDetails("UPG_FAILED")
		u.checkinNoDetails()
		res := u.waitResults()
		require.Equal(t, "upgrade failed", res[0].Error)
		require.Empty(t, u.agent().UpgradeStartedAt)
	})

	t.Run("requested rollback whose result could not be created is recorded as a success", func(t *testing.T) {
		u := newUpgradeTestWithData(t, ctx, srv, `{"version":"9.3.0","rollback":true}`)

		u.storeUpgradeDetails("UPG_ROLLBACK")
		u.checkinNoDetails()
		res := u.waitResults()
		require.Empty(t, res[0].Error)
	})

	t.Run("ack of a scheduled upgrade that ended without progressing records the result", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		// An upgrade to the current version: the agent acks it and later reports no upgrade_details.
		u.checkin(api.UpgradeDetailsStateUPGSCHEDULED, map[string]any{"scheduled_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)})
		u.ack("")
		res := u.waitResults()
		require.Empty(t, res[0].Error)

		u.checkinNoDetails()
		require.Len(t, u.results(), 1, "the no-details check-in must not create another result")
	})

	t.Run("rolled back upgrade without a reason", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.checkin(api.UpgradeDetailsStateUPGROLLBACK, nil)
		res := u.waitResults()
		require.Equal(t, "upgrade rolled back", res[0].Error)
	})

	t.Run("successful upgrade is recorded when the watch period ends", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.checkin(api.UpgradeDetailsStateUPGWATCHING, nil)
		u.ack("")
		require.Empty(t, u.results(), "no result while UPG_WATCHING")
		agent := u.agent()
		require.NotEmpty(t, agent.UpgradeStartedAt, "agent stays updating through UPG_WATCHING")
		require.Empty(t, agent.UpgradedAt)

		u.checkinNoDetails() // the watch period ended
		res := u.waitResults()
		require.Empty(t, res[0].Error)
		require.Equal(t, []string{"default"}, res[0].Namespaces)

		agent = u.agent()
		require.Empty(t, agent.UpgradeStartedAt)
		require.NotEmpty(t, agent.UpgradedAt)
		require.Nil(t, agent.UpgradeDetails)
	})

	t.Run("no result after a rollback when the details are cleared", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.checkin(api.UpgradeDetailsStateUPGROLLBACK, map[string]any{"reason": "watch failed"})
		u.waitResults()

		u.checkinNoDetails()
		res := u.results()
		require.Len(t, res, 1)
		require.NotEmpty(t, res[0].Error, "the rollback must not be overwritten by a success")
	})

	t.Run("ack without stored upgrade_details records the result", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		// An agent that predates upgrade_details, or a fast upgrade between check-ins.
		u.ack("")
		res := u.results()
		require.Len(t, res, 1)
		require.Empty(t, res[0].Error)
		agent := u.agent()
		require.Empty(t, agent.UpgradeStartedAt)
		require.NotEmpty(t, agent.UpgradedAt)
	})

	t.Run("ack carrying an error records the result even with matching upgrade_details", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.checkin(api.UpgradeDetailsStateUPGWATCHING, nil)
		u.ack("upgrade failed")
		res := u.results()
		require.Len(t, res, 1)
		require.Equal(t, "upgrade failed", res[0].Error)
	})

	t.Run("replayed ack does not create a second result", func(t *testing.T) {
		u := newUpgradeTest(t, ctx, srv)

		u.ack("")
		u.ack("")
		require.Len(t, u.results(), 1)
	})
}

// upgradeTest is an enrolled agent with a pending UPGRADE action.
type upgradeTest struct {
	t        *testing.T
	ctx      context.Context
	srv      *tserver
	agentID  string
	key      string
	actionID string
}

func newUpgradeTest(t *testing.T, ctx context.Context, srv *tserver) *upgradeTest {
	t.Helper()
	return newUpgradeTestWithData(t, ctx, srv, `{"version":"9.4.0"}`)
}

// newUpgradeTestWithData is newUpgradeTest for an UPGRADE action with the given data.
func newUpgradeTestWithData(t *testing.T, ctx context.Context, srv *tserver, data string) *upgradeTest {
	t.Helper()
	resp := EnrollAgent(t, ctx, srv, enrollBody)
	t.Cleanup(func() {
		if err := srv.bulker.Delete(context.Background(), dl.FleetAgents, resp.Item.Id); err != nil {
			t.Log("could not clean up agent")
		}
	})

	// Consume the initial POLICY_CHANGE action produced on the first checkin.
	initial := AgentCheckin(t, ctx, srv, resp.Item.Id, resp.Item.AccessApiKey)
	AgentAck(t, ctx, srv, initial, resp.Item.Id, resp.Item.AccessApiKey)

	u := &upgradeTest{
		t:        t,
		ctx:      ctx,
		srv:      srv,
		agentID:  resp.Item.Id,
		key:      resp.Item.AccessApiKey,
		actionID: uuid.Must(uuid.NewV4()).String(),
	}

	CreateActionDocument(t, ctx, srv, model.Action{
		Agents:     []string{u.agentID},
		Expiration: time.Now().Add(2000 * time.Hour).Format(time.RFC3339),
		ActionID:   u.actionID,
		Type:       string(api.UPGRADE),
		Data:       json.RawMessage(data),
		Namespaces: []string{"default"},
	})
	u.refresh(".fleet-actions")

	// Kibana marks the agent as updating when it creates the UPGRADE action.
	body, err := bulk.UpdateFields{dl.FieldUpgradeStartedAt: time.Now().UTC().Format(time.RFC3339)}.Marshal()
	require.NoError(t, err)
	require.NoError(t, srv.bulker.Update(ctx, dl.FleetAgents, u.agentID, body, bulk.WithRefresh()))
	return u
}

// checkin sends a check-in with upgrade_details in the given state. The check-in long polls, as no
// action is due, so it is cut short once Fleet Server has processed the upgrade_details.
func (u *upgradeTest) checkin(state api.UpgradeDetailsState, metadata map[string]any) {
	u.t.Helper()
	details := map[string]any{
		"target_version": "9.4.0",
		"state":          string(state),
		"action_id":      u.actionID,
	}
	if metadata != nil {
		details["metadata"] = metadata
	}
	u.send(details)
}

// storeUpgradeDetails stores upgrade_details in the given state on the agent, as left by a check-in
// whose result could not be created.
func (u *upgradeTest) storeUpgradeDetails(state string) {
	u.t.Helper()
	body, err := bulk.UpdateFields{dl.FieldUpgradeDetails: map[string]any{"action_id": u.actionID, "state": state}}.Marshal()
	require.NoError(u.t, err)
	require.NoError(u.t, u.srv.bulker.Update(u.ctx, dl.FleetAgents, u.agentID, body, bulk.WithRefresh()))
}

// checkinNoDetails sends a check-in without upgrade_details, which ends a watched upgrade.
func (u *upgradeTest) checkinNoDetails() {
	u.t.Helper()
	u.send(nil)
}

func (u *upgradeTest) send(details map[string]any) {
	u.t.Helper()
	var body map[string]any
	require.NoError(u.t, json.Unmarshal([]byte(checkinBody), &body))
	if details != nil {
		body["upgrade_details"] = details
	}
	p, err := json.Marshal(body)
	require.NoError(u.t, err)

	ctx, cancel := context.WithTimeout(u.ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.srv.baseURL()+"/api/fleet/agents/"+u.agentID+"/checkin", bytes.NewReader(p))
	require.NoError(u.t, err)
	req.Header.Set("Authorization", "ApiKey "+u.key)
	req.Header.Set("User-Agent", "elastic agent "+serverVersion)
	req.Header.Set("Content-Type", "application/json")
	res, err := cleanhttp.DefaultClient().Do(req)
	if errors.Is(err, context.DeadlineExceeded) {
		return // long polling
	}
	require.NoError(u.t, err)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		u.t.Fatalf("unexpected checkin status %d: %s", res.StatusCode, b)
	}
}

// ack acknowledges the UPGRADE action, with an error when errMsg is set.
func (u *upgradeTest) ack(errMsg string) {
	u.t.Helper()
	event := map[string]any{
		"action_id": u.actionID,
		"agent_id":  u.agentID,
		"message":   "test-message",
		"type":      "ACTION_RESULT",
		"subtype":   "ACKNOWLEDGED",
	}
	if errMsg != "" {
		event["error"] = errMsg
	}
	p, err := json.Marshal(map[string]any{"events": []any{event}})
	require.NoError(u.t, err)
	req, err := http.NewRequestWithContext(u.ctx, http.MethodPost, u.srv.baseURL()+"/api/fleet/agents/"+u.agentID+"/acks", bytes.NewReader(p))
	require.NoError(u.t, err)
	req.Header.Set("Authorization", "ApiKey "+u.key)
	req.Header.Set("Content-Type", "application/json")
	res, err := cleanhttp.DefaultClient().Do(req)
	require.NoError(u.t, err)
	defer res.Body.Close()
	require.Equal(u.t, http.StatusOK, res.StatusCode)
}

func (u *upgradeTest) refresh(index string) {
	u.t.Helper()
	client := u.srv.bulker.Client()
	res, err := client.Indices.Refresh(client.Indices.Refresh.WithIndex(index))
	require.NoError(u.t, err)
	res.Body.Close()
}

// results returns the action results of the agent for the UPGRADE action.
func (u *upgradeTest) results() []model.ActionResult {
	u.t.Helper()
	u.refresh(".fleet-actions-results")
	query := fmt.Sprintf(`{"query":{"bool":{"must":[{"term":{"action_id":%q}},{"term":{"agent_id":%q}}]}}}`, u.actionID, u.agentID)
	client := u.srv.bulker.Client()
	res, err := client.Search(
		client.Search.WithContext(u.ctx),
		client.Search.WithIndex(".fleet-actions-results"),
		client.Search.WithBody(strings.NewReader(query)),
	)
	require.NoError(u.t, err)
	defer res.Body.Close()

	var out GetActionResults
	require.NoError(u.t, json.NewDecoder(res.Body).Decode(&out))
	results := make([]model.ActionResult, 0, len(out.Hits.Hits))
	for _, h := range out.Hits.Hits {
		results = append(results, h.Result)
	}
	return results
}

// waitResults waits until the agent has its single result for the UPGRADE action and returns it.
func (u *upgradeTest) waitResults() []model.ActionResult {
	u.t.Helper()
	var res []model.ActionResult
	require.Eventually(u.t, func() bool {
		res = u.results()
		return len(res) == 1
	}, 10*time.Second, 500*time.Millisecond, "expected a result for the UPGRADE action")
	return res
}

func (u *upgradeTest) agent() model.Agent {
	u.t.Helper()
	res, err := u.srv.bulker.Client().Get(".fleet-agents", u.agentID)
	require.NoError(u.t, err)
	defer res.Body.Close()
	var out GetAgentResponse
	require.NoError(u.t, json.NewDecoder(res.Body).Decode(&out))
	return out.Agent
}
