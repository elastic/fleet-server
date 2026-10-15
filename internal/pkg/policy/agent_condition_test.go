// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAgentID = "agent-1"
	condSelf    = "${agent.id} == 'agent-1'"
	condOther   = "${agent.id} == 'agent-2'"
)

// testInput builds an input; the "n" field lets tests identify it after filtering.
func testInput(n int, condition string, streams ...any) map[string]any {
	in := map[string]any{"n": n}
	if condition != "" {
		in[fieldCondition] = condition
	}
	if streams != nil {
		in[fieldStreams] = streams
	}
	return in
}

func testStream(condition string) any {
	s := map[string]any{}
	if condition != "" {
		s[fieldCondition] = condition
	}
	return s
}

func remainingInputs(t *testing.T, inputs []map[string]any) []int {
	t.Helper()
	got := make([]int, 0, len(inputs))
	for _, in := range inputs {
		n, ok := in["n"].(int)
		require.True(t, ok)
		got = append(got, n)
	}
	return got
}

func TestFilterInputsForAgent(t *testing.T) {
	tests := []struct {
		name       string
		conditions []string
		want       []int
	}{
		{name: "no inputs"},
		{
			name:       "inputs pinned to another agent are dropped",
			conditions: []string{condSelf, condOther, ""},
			want:       []int{0, 2},
		},
		{
			name:       "unassigned sentinel runs nowhere",
			conditions: []string{"${agent.id} == '__synthetics_unassigned__'"},
		},
		{
			name: "any condition that can never be true for the agent is dropped",
			conditions: []string{
				"  ${agent.id}=='agent-2'  ",
				"${ agent.id } == 'agent-2'",
				"${agent.id|'z'} == 'agent-2'",
				"'agent-2' == ${agent.id}",
				"(" + condOther + ") and (${host.platform} == 'linux')",
				condOther + " or ${agent.id} == 'agent-3'",
				"${agent.id} == '${env.OWNER}'", // literals are never expanded
				condOther + " and arrayContains(${tags}, 'x')",
			},
		},
		{
			name: "conditions that may be true are left to the agent",
			conditions: []string{
				"${host.platform} != 'windows'",
				"(" + condOther + ") or (${host.platform} == 'linux')",
				condSelf + " and ${host.platform} == 'linux'",
				"${agent.id|'z'} == 'z'", // true if the agent provider is disabled
				"not (" + condOther + ")",
				"not (" + condSelf + ")", // true if the agent provider is disabled
				"true",
			},
			want: []int{0, 1, 2, 3, 4, 5, 6},
		},
		{
			name: "undecided conditions are left to the agent",
			conditions: []string{
				"${agent.id} == 'a'b'",                     // syntax error
				"${agent.id} == 'agent-2' and $${x}",       // always fails
				"${agent.id} > 5",                          // always fails
				"${agent.id} == 'agent-2' and ${a-b} == 1", // '-' in names needs agent 8.4
			},
			want: []int{0, 1, 2, 3},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputs := make([]map[string]any, 0, len(tc.conditions))
			for i, c := range tc.conditions {
				inputs = append(inputs, testInput(i, c))
			}
			got, _ := FilterInputsForAgent(inputs, nil, testAgentID, false)
			assert.ElementsMatch(t, tc.want, remainingInputs(t, got))
		})
	}
}

func TestFilterInputsForAgent_Streams(t *testing.T) {
	inputs := []map[string]any{
		testInput(0, "", testStream(condSelf), testStream(condOther), testStream("")),
		testInput(1, "", testStream(condOther)),
		testInput(2, "", testStream(condSelf)),
		testInput(3, "", []any{}...),
	}

	got, _ := FilterInputsForAgent(inputs, nil, testAgentID, false)

	assert.Equal(t, []int{0, 2, 3}, remainingInputs(t, got))
	assert.Equal(t, []any{testStream(condSelf), testStream("")}, got[0][fieldStreams])

	// shared inputs must not be mutated
	assert.Len(t, inputs, 4)
	assert.Len(t, inputs[0][fieldStreams], 3)
}

// Elastic Agent before 8.6.0 keeps an input whose streams were all removed.
func TestFilterInputsForAgent_KeepStreamless(t *testing.T) {
	inputs := []map[string]any{
		testInput(0, condOther, testStream(condSelf)),
		testInput(1, "", testStream(condOther), testStream(condOther)),
		testInput(2, "", testStream(condOther), testStream(condSelf)),
	}
	// {before, after}; an empty "after" means the key is dropped.
	cases := [][2]string{
		{"inputs.0.drop", ""},
		{"inputs.1.keep", "inputs.0.keep"},
		{"inputs.1.streams.1.drop", ""},
		{"inputs.2.streams.1.keep", "inputs.1.streams.0.keep"},
	}
	keys := make([]string, 0, len(cases))
	want := make([]string, 0, len(cases))
	for _, c := range cases {
		keys = append(keys, c[0])
		if c[1] != "" {
			want = append(want, c[1])
		}
	}

	got, gotKeys := FilterInputsForAgent(inputs, keys, testAgentID, true)

	assert.Equal(t, []int{1, 2}, remainingInputs(t, got))
	assert.Equal(t, []any{}, got[0][fieldStreams])
	assert.Equal(t, []any{testStream(condSelf)}, got[1][fieldStreams])
	assert.ElementsMatch(t, want, gotKeys)
	assert.Len(t, inputs[1][fieldStreams], 2, "shared inputs must not be mutated")
}

// The agent evaluates an input's own condition before dropping it for having
// no streams left; if that may fail, the input is left for the agent.
func TestFilterInputsForAgent_StreamlessInputConditionMayFail(t *testing.T) {
	inputs := []map[string]any{
		testInput(0, "${agent.id} == 'agent-1", testStream(condOther)),
		testInput(1, "${host.platform} > 5 and $${x}", testStream(condOther)),
		testInput(2, "${host.platform} == 'linux'", testStream(condOther)),
		testInput(3, "", testStream(condOther)),
	}
	inputs[3][fieldCondition] = 42

	got, _ := FilterInputsForAgent(inputs, nil, testAgentID, false)

	assert.Equal(t, []int{0, 1, 3}, remainingInputs(t, got))
	for _, in := range got {
		assert.Len(t, in[fieldStreams], 1, "input %v must be left as is", in["n"])
	}
}

func TestFilterInputsForAgent_NothingPrunedReturnsOriginal(t *testing.T) {
	inputs := []map[string]any{testInput(0, condSelf), testInput(1, "")}
	keys := []string{"inputs.0.secret"}

	got, gotKeys := FilterInputsForAgent(inputs, keys, testAgentID, false)

	require.Len(t, got, 2)
	assert.Same(t, &inputs[0], &got[0])
	assert.Equal(t, keys, gotKeys)
}

func TestFilterInputsForAgent_RemapsSecretKeys(t *testing.T) {
	inputs := []map[string]any{
		testInput(0, condOther),
		testInput(1, "", testStream(condOther), testStream(condSelf), testStream("")),
		testInput(2, ""),
		testInput(3, "", testStream(condOther)),
		testInput(4, ""),
	}
	// {before, after}; an empty "after" means the key is dropped.
	cases := [][2]string{
		{"inputs.0.dropped", ""},
		{"inputs.1.var", "inputs.0.var"},
		{"inputs.1.streams.0.var", ""},
		{"inputs.1.streams.1.var", "inputs.0.streams.0.var"},
		{"inputs.1.streams.2.nested.0.var", "inputs.0.streams.1.nested.0.var"},
		{"inputs.2.other", "inputs.1.other"},
		{"inputs.3.streams.0.var", ""},
		{"inputs.4", "inputs.2"},
	}
	// Keys outside the pruned inputs, or out of range, pass through untouched.
	passthrough := []string{"outputs.default.ssl.key", "inputs.9.out-of-range", "fleet.hosts"}
	keys := append([]string(nil), passthrough...)
	want := append([]string(nil), passthrough...)
	for _, c := range cases {
		keys = append(keys, c[0])
		if c[1] != "" {
			want = append(want, c[1])
		}
	}
	original := append([]string(nil), keys...)

	got, gotKeys := FilterInputsForAgent(inputs, keys, testAgentID, false)

	assert.Equal(t, []int{1, 2, 4}, remainingInputs(t, got))
	assert.ElementsMatch(t, want, gotKeys)
	assert.Equal(t, original, keys, "input keys must not be mutated")
}

// BenchmarkFilterInputsForAgent measures a Synthetics private location with
// 10k monitors sharded over 100 agents.
func BenchmarkFilterInputsForAgent(b *testing.B) {
	inputs := make([]map[string]any, 10000)
	for i := range inputs {
		inputs[i] = testInput(i, fmt.Sprintf("${agent.id} == 'agent-%d'", i%100))
	}
	b.ReportAllocs()
	for b.Loop() {
		FilterInputsForAgent(inputs, nil, testAgentID, false)
	}
}
