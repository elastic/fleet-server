// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// An UPGRADE action result is recorded from the check-in upgrade_details once the outcome of the
// upgrade is known, instead of from the UPGRADE ack (elastic/fleet-server#8274).

// upgradeRetryGrace is added to the agent-reported retry_until to tolerate clock skew between the
// agent and Fleet Server.
const upgradeRetryGrace = time.Minute

// upgradeOutcome is how an upgrade ended, as recorded on its action result.
type upgradeOutcome struct {
	errMsg   string // empty for a successful upgrade
	rollback bool   // the agent reported UPG_ROLLBACK
}

// errorFor returns the error to record for the UPGRADE action. UPG_ROLLBACK is a failure when the
// agent rolled an upgrade back by itself (e.g. the watch failed), but it is the successful
// outcome of an action that asked for the rollback.
func (o upgradeOutcome) errorFor(action *model.Action) string {
	if o.rollback && action != nil && isRollbackAction(*action) {
		return ""
	}
	return o.errMsg
}

// isRollbackAction reports whether the UPGRADE action asks the agent to roll back (data.rollback).
func isRollbackAction(action model.Action) bool {
	var data struct {
		Rollback bool `json:"rollback"`
	}
	if err := json.Unmarshal(action.Data, &data); err != nil {
		return false
	}
	return data.Rollback
}

// upgradeFailureIsFinal reports whether a UPG_FAILED check-in is the final outcome of the upgrade.
// The agent reports UPG_FAILED for each failed download attempt and keeps retrying until
// metadata.retry_until, without clearing it when the retries are exhausted. A failure is therefore
// final once retry_until has passed; with no retry_until (every non-download failure) it is final
// at once. The decision uses the check-in alone, so any Fleet Server instance reaches the same one.
func upgradeFailureIsFinal(m *UpgradeDetails_Metadata, now time.Time) bool {
	if m == nil {
		return true
	}
	meta, err := m.AsUpgradeMetadataDownloading()
	if err != nil || meta.RetryUntil == nil || meta.RetryUntil.IsZero() {
		return true
	}
	return now.After(meta.RetryUntil.Add(upgradeRetryGrace))
}

// upgradeCompleted reports whether an agent that checked in without upgrade_details has completed
// the stored upgrade. ver is non-empty when the agent's version changed. A stored upgrade that
// never started, e.g. UPG_SCHEDULED after the agent dropped the queued upgrade on a cancel action,
// is not completed, and UPG_FAILED and UPG_ROLLBACK already have their result.
func upgradeCompleted(ud *model.UpgradeDetails, ver string) bool {
	switch ud.State {
	case string(UpgradeDetailsStateUPGFAILED), string(UpgradeDetailsStateUPGROLLBACK):
		return false
	case string(UpgradeDetailsStateUPGWATCHING):
		return true
	}
	return ver != ""
}

// rollbackError builds the action result error for a UPG_ROLLBACK state from metadata.reason, e.g.
// "upgrade rolled back: watch failed". UPG_ROLLBACK carries no error_msg.
func rollbackError(m *UpgradeDetails_Metadata) string {
	const msg = "upgrade rolled back"
	if m == nil {
		return msg
	}
	raw, err := m.MarshalJSON()
	if err != nil {
		return msg
	}
	var meta struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Reason == "" {
		return msg
	}
	return msg + ": " + meta.Reason
}

// createUpgradeResult creates the UPGRADE action result for the agent (no refresh, an existing
// result is not an error).
func (ct *CheckinT) createUpgradeResult(ctx context.Context, agent *model.Agent, actionID string, outcome upgradeOutcome) error {
	span, ctx := apm.StartSpan(ctx, "Create upgrade result", "update")
	span.Context.SetLabel("action_id", actionID)
	span.Context.SetLabel("agent_id", agent.Agent.ID)
	defer span.End()

	// Always read the action from Elasticsearch: the action cache only retains the action ID and
	// type, so a cache hit would not provide the namespaces the result must carry. This runs once,
	// when the outcome is known, so the extra read is cheap.
	actions, err := dl.FindAction(ctx, ct.bulker, actionID)
	if err != nil {
		return fmt.Errorf("unable to find upgrade action %q: %w", actionID, err)
	}
	var action *model.Action
	if len(actions) > 0 {
		action = &actions[0]
	} else {
		zerolog.Ctx(ctx).Warn().Str(ecs.ActionID, actionID).Str(ecs.AgentID, agent.Agent.ID).Msg("upgrade action not found, creating result without namespaces")
	}

	result := model.ActionResult{
		ActionID: actionID,
		AgentID:  agent.Id,
		Error:    outcome.errorFor(action),
	}
	if action != nil {
		result.Namespaces = action.Namespaces
	}
	return dl.CreateActionResult(ctx, ct.bulker, result)
}
