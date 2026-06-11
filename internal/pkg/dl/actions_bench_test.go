// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
)

// BenchmarkFindAgentActionsRender measures the full render path for
// FindAgentActions: params map construction, time formatting, and template
// rendering. This is on the critical path for every agent check-in.
func BenchmarkFindAgentActionsRender(b *testing.B) {
	minSeqNo := sqn.SeqNo{0}
	maxSeqNo := sqn.SeqNo{100}
	const agentID = "test-agent-id-0123456789abcdef0123"

	b.ReportAllocs()
	for b.Loop() {
		params := map[string]any{
			FieldSeqNo:      minSeqNo.Value(),
			FieldMaxSeqNo:   maxSeqNo.Value(),
			FieldExpiration: time.Now().UTC().Format(time.RFC3339),
			FieldAgents:     []string{agentID},
		}
		_, err := QueryAgentActions.Render(params)
		if err != nil {
			b.Fatal(err)
		}
	}
}
