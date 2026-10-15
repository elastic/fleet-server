// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package policy

import (
	"maps"
	"strconv"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/policy/eql"
)

const (
	fieldCondition = "condition"
	fieldStreams   = "streams"

	secretKeyInputsPrefix = "inputs."
	secretKeyStreamsInfix = fieldStreams + "."
	removed               = -1
)

// FilterInputsForAgent drops the inputs and streams that Elastic Agent agentID
// would never run because their condition, which must reference ${agent.id},
// can never be true for it (see package eql). Anything undecided is left for
// the agent. Secret key paths are renumbered to follow the shifted indexes.
// Input elements are shared between agents, so changed inputs are copied,
// never mutated.
//
// Elastic Agent before 8.6.0 keeps an input whose streams were all removed by
// conditions, as `streams: []`; keepStreamless reproduces that for such agents.
func FilterInputsForAgent(inputs []map[string]any, secretKeys []string, agentID string, keepStreamless bool) ([]map[string]any, []string) {
	out := make([]map[string]any, 0, len(inputs))
	inputIdx := make([]int, len(inputs))
	streamIdx := make(map[int][]int)
	changed := false

	for i, input := range inputs {
		filtered, sIdx, keep := filterInput(input, agentID, keepStreamless)
		if !keep {
			inputIdx[i] = removed
			changed = true
			continue
		}
		inputIdx[i] = len(out)
		if filtered != nil {
			input = filtered
			streamIdx[i] = sIdx
			changed = true
		}
		out = append(out, input)
	}
	if !changed {
		return inputs, secretKeys
	}
	return out, remapSecretKeys(secretKeys, inputIdx, streamIdx)
}

// filterInput returns a modified copy (plus new stream indexes) when streams
// were pruned, or nil when the original input is kept as is.
func filterInput(input map[string]any, agentID string, keepStreamless bool) (map[string]any, []int, bool) {
	if neverTrue(input[fieldCondition], agentID) {
		return nil, nil, false
	}

	streams, ok := input[fieldStreams].([]any)
	if !ok || len(streams) == 0 {
		return nil, nil, true
	}

	kept := make([]any, 0, len(streams))
	idx := make([]int, len(streams))
	for j, s := range streams {
		if stream, ok := s.(map[string]any); ok && neverTrue(stream[fieldCondition], agentID) {
			idx[j] = removed
			continue
		}
		idx[j] = len(kept)
		kept = append(kept, s)
	}
	switch {
	case len(kept) == len(streams):
		return nil, nil, true
	case len(kept) == 0 && !keepStreamless:
		// The agent drops an input left without streams, but only after
		// evaluating its own condition: keep the input as is if that may fail.
		if !conditionMayEvaluate(input[fieldCondition], agentID) {
			return nil, nil, true
		}
		return nil, nil, false
	}

	cp := maps.Clone(input)
	cp[fieldStreams] = kept
	return cp, idx, true
}

func neverTrue(condition any, agentID string) bool {
	s, ok := condition.(string)
	return ok && eql.NeverTrue(s, agentID)
}

func conditionMayEvaluate(condition any, agentID string) bool {
	switch c := condition.(type) {
	case nil, bool:
		return true
	case string:
		return eql.MayEvaluate(c, agentID)
	}
	return false
}

func remapSecretKeys(keys []string, inputIdx []int, streamIdx map[int][]int) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if k, ok := remapSecretKey(key, inputIdx, streamIdx); ok {
			out = append(out, k)
		}
	}
	return out
}

func remapSecretKey(key string, inputIdx []int, streamIdx map[int][]int) (string, bool) {
	rest, ok := strings.CutPrefix(key, secretKeyInputsPrefix)
	if !ok {
		return key, true
	}
	i, rest, ok := cutIndex(rest)
	if !ok || i >= len(inputIdx) {
		return key, true
	}
	ni := inputIdx[i]
	if ni == removed {
		return "", false
	}

	prefix := secretKeyInputsPrefix + strconv.Itoa(ni)
	sIdx := streamIdx[i]
	streamRest, isStream := strings.CutPrefix(rest, secretKeyStreamsInfix)
	if sIdx == nil || !isStream {
		if rest == "" {
			return prefix, true
		}
		return prefix + "." + rest, true
	}
	j, tail, ok := cutIndex(streamRest)
	if !ok || j >= len(sIdx) {
		return prefix + "." + rest, true
	}
	if sIdx[j] == removed {
		return "", false
	}
	out := prefix + "." + secretKeyStreamsInfix + strconv.Itoa(sIdx[j])
	if tail != "" {
		out += "." + tail
	}
	return out, true
}

func cutIndex(s string) (int, string, bool) {
	head, rest, _ := strings.Cut(s, ".")
	n, err := strconv.Atoi(head)
	if err != nil || n < 0 {
		return 0, "", false
	}
	return n, rest, true
}
