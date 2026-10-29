// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryAgentActionsForUninstallFiltersByType verifies that the
// pending-uninstall agent-actions query restricts results by action type in the
// query itself (so withheld actions cannot consume the bounded fetch window),
// while the default agent-actions query does not.
func TestQueryAgentActionsForUninstallFiltersByType(t *testing.T) {
	q, err := QueryAgentActionsForUninstall.Render(map[string]any{
		FieldSeqNo:      int64(0),
		FieldMaxSeqNo:   int64(10),
		FieldExpiration: "2026-01-01T00:00:00Z",
		FieldAgents:     []string{"agent-1"},
		FiledType:       []string{"UNINSTALL", "CANCEL"},
	})
	require.NoError(t, err)
	s := string(q)
	assert.Contains(t, s, `"type"`, "query must filter on the action type field")
	assert.Contains(t, s, "UNINSTALL")
	assert.Contains(t, s, "CANCEL")

	// The default agent-actions query must not restrict by type.
	def, err := QueryAgentActions.Render(map[string]any{
		FieldSeqNo:      int64(0),
		FieldMaxSeqNo:   int64(10),
		FieldExpiration: "2026-01-01T00:00:00Z",
		FieldAgents:     []string{"agent-1"},
	})
	require.NoError(t, err)
	assert.NotContains(t, string(def), "UNINSTALL")
}
