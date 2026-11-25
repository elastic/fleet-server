// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

func TestUpgradeFailureIsFinal(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	metadata := func(retryUntil time.Time) *UpgradeDetails_Metadata {
		return &UpgradeDetails_Metadata{json.RawMessage(`{"error_msg":"failed","retry_until":"` + retryUntil.Format(time.RFC3339) + `"}`)}
	}

	tests := []struct {
		name string
		meta *UpgradeDetails_Metadata
		want bool
	}{
		{"no metadata", nil, true},
		{"no retry_until, e.g. a failure after the download", &UpgradeDetails_Metadata{json.RawMessage(`{"error_msg":"failed","failed_state":"UPG_EXTRACTING"}`)}, true},
		{"unparseable retry_until", &UpgradeDetails_Metadata{json.RawMessage(`{"retry_until":"soon"}`)}, true},
		{"retry_until in the future, the download can still be retried", metadata(now.Add(time.Hour)), false},
		{"retry_until passed within the clock skew grace", metadata(now.Add(-upgradeRetryGrace / 2)), false},
		{"retry_until passed beyond the clock skew grace", metadata(now.Add(-2 * upgradeRetryGrace)), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, upgradeFailureIsFinal(tc.meta, now))
		})
	}
}

func TestNoDetailsOutcome(t *testing.T) {
	success := upgradeOutcome{}
	failed := upgradeOutcome{errMsg: "upgrade failed"}
	rolledBack := upgradeOutcome{errMsg: "upgrade rolled back", rollback: true}

	tests := []struct {
		name      string
		state     UpgradeDetailsState
		unsettled bool // upgrade_started_at is still set
		ver       string
		want      upgradeOutcome
		record    bool
	}{
		{"watch period ended", UpgradeDetailsStateUPGWATCHING, true, "", success, true},
		{"version changed after the restart", UpgradeDetailsStateUPGRESTARTING, true, "9.4.0", success, true},
		{"version unchanged while the upgrade is in progress", UpgradeDetailsStateUPGDOWNLOADING, true, "", success, false},
		{"scheduled upgrade the agent dropped on a cancel action", UpgradeDetailsStateUPGSCHEDULED, true, "", success, false},
		{"failure whose result could not be created", UpgradeDetailsStateUPGFAILED, true, "", failed, true},
		{"failure that already has its result", UpgradeDetailsStateUPGFAILED, false, "9.4.0", failed, false},
		{"rollback whose result could not be created", UpgradeDetailsStateUPGROLLBACK, true, "9.3.0", rolledBack, true},
		{"rollback that already has its result", UpgradeDetailsStateUPGROLLBACK, false, "9.3.0", rolledBack, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			agent := &model.Agent{UpgradeDetails: &model.UpgradeDetails{ActionID: "test-action", State: string(tc.state)}}
			if tc.unsettled {
				agent.UpgradeStartedAt = "2026-01-01T00:00:00Z"
			}
			outcome, record := noDetailsOutcome(agent, tc.ver)
			assert.Equal(t, tc.record, record)
			if tc.record {
				assert.Equal(t, tc.want, outcome)
			}
		})
	}
}

func TestRollbackError(t *testing.T) {
	assert.Equal(t, "upgrade rolled back", rollbackError(nil))
	assert.Equal(t, "upgrade rolled back", rollbackError(&UpgradeDetails_Metadata{json.RawMessage(`{}`)}))
	assert.Equal(t, "upgrade rolled back: watch failed", rollbackError(&UpgradeDetails_Metadata{json.RawMessage(`{"reason":"watch failed"}`)}))
}

func TestUpgradeOutcomeErrorFor(t *testing.T) {
	upgrade := &model.Action{Data: json.RawMessage(`{"version":"9.4.0"}`)}
	rollbackRequest := &model.Action{Data: json.RawMessage(`{"version":"9.3.0","rollback":true}`)}

	failed := upgradeOutcome{errMsg: "download failed"}
	rolledBack := upgradeOutcome{errMsg: "upgrade rolled back: watch failed", rollback: true}

	assert.Equal(t, "download failed", failed.errorFor(upgrade))
	assert.Equal(t, "upgrade rolled back: watch failed", rolledBack.errorFor(upgrade), "the agent rolled the upgrade back by itself")
	assert.Equal(t, "upgrade rolled back: watch failed", rolledBack.errorFor(nil), "without the action it is a failure")
	assert.Empty(t, rolledBack.errorFor(rollbackRequest), "the action asked for the rollback")
	assert.Empty(t, upgradeOutcome{}.errorFor(upgrade), "success")
}
