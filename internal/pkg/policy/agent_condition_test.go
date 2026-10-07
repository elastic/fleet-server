// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterInputsForAgent(t *testing.T) {
	const self = "agent-1"
	pinned := func(id string) string { return "${agent.id} == '" + id + "'" }

	tests := []struct {
		name   string
		inputs []map[string]any
		want   []string // ids of the inputs expected to remain
	}{
		{
			name:   "no inputs",
			inputs: nil,
		},
		{
			name: "input condition for another agent is dropped",
			inputs: []map[string]any{
				{"id": "mine", "condition": pinned(self)},
				{"id": "other", "condition": pinned("agent-2")},
			},
			want: []string{"mine"},
		},
		{
			name: "unassigned sentinel runs nowhere",
			inputs: []map[string]any{
				{"id": "unassigned", "condition": pinned("__synthetics_unassigned__")},
			},
		},
		{
			name: "other conditions and unconditioned inputs are kept",
			inputs: []map[string]any{
				{"id": "none"},
				{"id": "platform", "condition": "${host.platform} != 'windows'"},
				{"id": "combined", "condition": "(" + pinned("agent-2") + ") and (${host.platform} == 'linux')"},
				{"id": "not-a-string", "condition": true},
				{"id": "quote", "condition": "${agent.id} == 'a'b'"},
			},
			want: []string{"none", "platform", "combined", "not-a-string", "quote"},
		},
		{
			name: "whitespace tolerant",
			inputs: []map[string]any{
				{"id": "other", "condition": "  ${agent.id}=='agent-2'  "},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FilterInputsForAgent(tc.inputs, self)
			ids := make([]string, 0, len(got))
			for _, in := range got {
				id, ok := in["id"].(string)
				require.True(t, ok)
				ids = append(ids, id)
			}
			if len(tc.want) == 0 {
				assert.Empty(t, ids)
				return
			}
			assert.Equal(t, tc.want, ids)
		})
	}
}

func TestFilterInputsForAgent_Streams(t *testing.T) {
	const self = "agent-1"
	stream := func(id, cond string) any {
		s := map[string]any{"id": id}
		if cond != "" {
			s["condition"] = cond
		}
		return s
	}
	mine := "${agent.id} == 'agent-1'"
	other := "${agent.id} == 'agent-2'"

	inputs := []map[string]any{
		{"id": "mixed", "streams": []any{stream("a", mine), stream("b", other), stream("c", "")}},
		{"id": "all-other", "streams": []any{stream("d", other)}},
		{"id": "untouched", "streams": []any{stream("e", mine)}},
		{"id": "no-streams", "streams": []any{}},
	}

	got := FilterInputsForAgent(inputs, self)

	require.Len(t, got, 3)
	assert.Equal(t, "mixed", got[0]["id"])
	assert.Equal(t, []any{stream("a", mine), stream("c", "")}, got[0]["streams"])
	assert.Equal(t, "untouched", got[1]["id"])
	assert.Equal(t, "no-streams", got[2]["id"])

	// shared inputs must not be mutated
	assert.Len(t, inputs[0]["streams"], 3)
	assert.Len(t, inputs, 4)
}

func TestFilterInputsForAgent_NothingPrunedReturnsOriginal(t *testing.T) {
	inputs := []map[string]any{
		{"id": "a", "condition": "${agent.id} == 'agent-1'"},
		{"id": "b"},
	}
	got := FilterInputsForAgent(inputs, "agent-1")
	require.Len(t, got, 2)
	assert.Same(t, &inputs[0], &got[0])
}
