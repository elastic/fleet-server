// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package policy

import (
	"maps"
	"regexp"
)

const (
	fieldCondition = "condition"
	fieldStreams   = "streams"
)

// agentIDConditionRE matches the only condition shape pruned server-side:
// ${agent.id} == '<literal>'. EQL single-quoted literals have no escape
// sequences, so a literal containing a quote or backslash is never matched and
// is left for the agent to evaluate.
var agentIDConditionRE = regexp.MustCompile(`^\s*\$\{agent\.id\}\s*==\s*'([^'\\\x00-\x1f]*)'\s*$`)

// FilterInputsForAgent removes inputs and streams whose condition pins them to
// a different agent id, mirroring what Elastic Agent does after receiving the
// policy (an input left with no streams is removed). It never mutates inputs:
// the elements are shared between all agents of a policy, so changed inputs are
// copied, and the original slice is returned when nothing is pruned.
func FilterInputsForAgent(inputs []map[string]any, agentID string) []map[string]any {
	out := make([]map[string]any, 0, len(inputs))
	changed := false
	for _, input := range inputs {
		filtered, keep := filterInput(input, agentID)
		if !keep {
			changed = true
			continue
		}
		if filtered != nil {
			changed = true
			input = filtered
		}
		out = append(out, input)
	}
	if !changed {
		return inputs
	}
	return out
}

// filterInput returns keep=false when the input must be dropped. A non-nil
// map is a modified copy; nil means the original input is used as is.
func filterInput(input map[string]any, agentID string) (map[string]any, bool) {
	if pinnedToOtherAgent(input[fieldCondition], agentID) {
		return nil, false
	}

	streams, ok := input[fieldStreams].([]any)
	if !ok || len(streams) == 0 {
		return nil, true
	}

	kept := make([]any, 0, len(streams))
	for _, s := range streams {
		if stream, ok := s.(map[string]any); ok && pinnedToOtherAgent(stream[fieldCondition], agentID) {
			continue
		}
		kept = append(kept, s)
	}
	switch len(kept) {
	case len(streams):
		return nil, true
	case 0:
		return nil, false
	}

	cp := maps.Clone(input)
	cp[fieldStreams] = kept
	return cp, true
}

func pinnedToOtherAgent(condition any, agentID string) bool {
	s, ok := condition.(string)
	if !ok {
		return false
	}
	m := agentIDConditionRE.FindStringSubmatch(s)
	return m != nil && m[1] != agentID
}
