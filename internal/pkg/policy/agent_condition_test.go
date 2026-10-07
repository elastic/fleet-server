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
			got, _ := FilterInputsForAgent(tc.inputs, nil, self)
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

	got, _ := FilterInputsForAgent(inputs, nil, self)

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
	got, _ := FilterInputsForAgent(inputs, nil, "agent-1")
	require.Len(t, got, 2)
	assert.Same(t, &inputs[0], &got[0])
}

func TestFilterInputsForAgent_RemapsSecretKeys(t *testing.T) {
	const self = "agent-1"
	mine := "${agent.id} == 'agent-1'"
	other := "${agent.id} == 'agent-2'"
	stream := func(cond string) any { return map[string]any{"condition": cond} }

	inputs := []map[string]any{
		{"id": "removed", "condition": other},
		{"id": "kept", "streams": []any{stream(other), stream(mine), stream("")}},
		{"id": "plain"},
		{"id": "all-streams-removed", "streams": []any{stream(other)}},
		{"id": "last"},
	}
	keys := []string{
		"outputs.default.ssl.key",
		"inputs.0.var",
		"inputs.1.var",
		"inputs.1.streams.0.var",
		"inputs.1.streams.1.var",
		"inputs.1.streams.2.nested.0.var",
		"inputs.2.var",
		"inputs.3.streams.0.var",
		"inputs.4",
		"inputs.9.out-of-range",
		"fleet.hosts",
	}

	gotInputs, gotKeys := FilterInputsForAgent(inputs, keys, self)

	require.Len(t, gotInputs, 3)
	assert.Equal(t, []string{
		"outputs.default.ssl.key",
		"inputs.0.var",
		"inputs.0.streams.0.var",
		"inputs.0.streams.1.nested.0.var",
		"inputs.1.var",
		"inputs.2",
		"inputs.9.out-of-range",
		"fleet.hosts",
	}, gotKeys)
	assert.Len(t, keys, 11, "input keys must not be mutated")
}

func TestFilterInputsForAgent_NothingPrunedKeepsSecretKeys(t *testing.T) {
	keys := []string{"inputs.0.var"}
	_, got := FilterInputsForAgent([]map[string]any{{"id": "a"}}, keys, "agent-1")
	assert.Equal(t, keys, got)
}
