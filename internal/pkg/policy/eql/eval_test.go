// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eql

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	self      = "agent-1"
	other     = "${agent.id} == 'agent-2'"
	pinned    = "${agent.id} == 'agent-1'"
	fallbackZ = "${agent.id|'z'} == 'z'"
	idGT5     = "${agent.id} > 5"
	platform  = "host.platform"
	linux     = "linux"

	// Results, as the agent's eql.Eval reports them.
	rTrue      = "true"
	rFalse     = "false"
	rError     = "error"
	rUndecided = "undecided"
)

func TestNeverTrue(t *testing.T) {
	tests := []struct {
		name  string
		conds []string
		want  bool
	}{
		{
			name: "pinned to another agent",
			want: true,
			conds: []string{
				other,
				"${agent.id}=='agent-2'",
				"  ${agent.id} == 'agent-2'  ",
				"\t${agent.id}\r\n==\n'agent-2'",
				"${ agent.id } == 'agent-2'",
				"${agent.id} == \"agent-2\"",
				"'agent-2' == ${agent.id}",
				"${agent.id} == 'AGENT-1'", // case-sensitive
				"${agent.id} == ''",
				"${agent.id} == '${env.OWNER}'", // literals are never expanded
				"(" + other + ")",
				"((" + other + "))",
				"${agent.id|'z'} == 'agent-2'",
				"${agent.id} == 'agent-2' or ${agent.id} == 'agent-3'",
				"${agent.id} == 'agent-2' OR ${agent.id} == 'agent-3'",
				"(" + other + ") and (${host.platform} == 'linux')",
				other + " AND ${host.platform} == 'linux'",
				"${host.platform} == 'linux' and " + other,
				other + " and arrayContains(${tags}, 'x')",
				other + " and ${a} > 5",
				"not (${agent.id} != 'agent-2')",
				"NOT (${agent.id} == 'agent-1' or ${agent.id} != 'agent-2')",
			},
		},
		{
			name: "may be true for the agent",
			conds: []string{
				pinned,
				"${agent.id} != 'agent-2'",
				"(" + other + ") or (${host.platform} == 'linux')",
				other + " or true",
				pinned + " and ${host.platform} == 'linux'",
				"not (" + other + ")",
				// ${agent.id} is unset when the agent provider is disabled.
				fallbackZ,
				"not (" + pinned + ")",
				"${agent.id} != 'agent-1'",
				"${agent.id|host.name} == 'agent-2'",
				"${a|agent.id} == 'agent-2'", // ${a} may hold anything
				"${agent.id} == 'agent-2' == false",
			},
		},
		{
			name: "never decided without ${agent.id}",
			conds: []string{
				"false == true",
				"1 == 2",
				"${host.platform} == 'linux' and false",
			},
		},
		{
			name: "always fails on the agent",
			conds: []string{
				idGT5,
				"${agent.id} == 'agent-2' and $${agent.id}",
				"${agent.id} == 'agent-2' and 5",
				"${agent.id}",
				"5 == ${agent.id}",
			},
		},
		{
			name: "rejected by the agent's parser",
			conds: []string{
				"${agent.id} == 'agent-2",
				"${agent.id} == agent-2",
				"${agent.id} = 'agent-2'",
				"${agent.id}\f== 'agent-2'",
				"${agent.id} == 'agent-2' ==",
				"${agent.id} == 'a'b'",
				"${agent.id} == 'a\nb'",
				"${agent.id} == 'agent-2' and",
				"${agent.id} == 'agent-2')",
				"${agent.id} == 'agent-2' $",
				"${agent.id} == 'ägent' and ä",
			},
		},
		{
			name: "not parsed the same by every agent version",
			conds: []string{
				other + " and ${kubernetes.labels.app-name} == 'x'",
				other + " and ${a/b} == 'x'",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range tc.conds {
				assert.Equal(t, tc.want, NeverTrue(c, self), c)
			}
		})
	}
}

// Expected results are those of Elastic Agent's eql.Eval for the same input.
func TestEvalMatchesAgent(t *testing.T) {
	vars := map[string]any{agentIDVar: self, platform: linux, "n": 5, "f": 1.5, "b": true, "tags": []any{"x", "y"}}
	tests := map[string]string{
		// precedence: each binary operator has its own level, NOT sits between +- and ==
		"not ${b} == false":              rTrue,
		"not 1 + 1":                      rError,
		"${n} == 5 != false":             rTrue,
		"false != ${n} == 5":             rTrue,
		"true or false and false":        rTrue,
		"(true or false) and false":      rFalse,
		"1 + 2 * 3 == 7":                 rTrue,  // arithmetic: undecided here
		"${n} < 6 == true":               rError, // == binds tighter than <
		"${n} > 4 and ${n} >= 5":         rTrue,
		"${f} < ${n} and ${n} <= 5":      rTrue,
		"${agent.id|'z'} == 'agent-1'":   rTrue,
		"${missing|'z'} == 'z'":          rTrue,
		"${missing} == ${other.missing}": rTrue,
		"${missing} != 'x'":              rTrue,
		"${tags} == ['x', 'y']":          rTrue,
		"${tags} != ['x']":               rTrue,
		"'a' == 1":                       rFalse,
		"1 == 'a'":                       rError,
		"1 == 1.0":                       rTrue,
		"${host.platform} == ${missing}": rFalse,
		"${missing} and true":            rError,
		"${n} or true":                   rError,
		"TRUE AND NOT FALSE":             rTrue,
		"${host.platform}":               rError,
		"\"linux\" == ${host.platform}":  rTrue,
		pinned + " == true":              rTrue,
	}
	for cond, want := range tests {
		n, err := parse(cond)
		require.NoError(t, err, cond)
		ev := evaluator{vars: vars}
		got := rUndecided
		switch ev.eval(n).topLevel() {
		case oTrue:
			got = rTrue
		case oFalse:
			got = rFalse
		case oError:
			got = rError
		}
		if got == rUndecided {
			continue // arithmetic and functions are not evaluated; never decides a prune
		}
		assert.Equal(t, want, got, cond)
	}
}

func TestParseLimits(t *testing.T) {
	deep := strings.Repeat("(", maxDepth+1) + other + strings.Repeat(")", maxDepth+1)
	assert.False(t, NeverTrue(deep, self))

	long := other + strings.Repeat(" ", maxLen)
	assert.False(t, NeverTrue(long, self))

	assert.False(t, NeverTrue("", self))
}

func TestMayEvaluate(t *testing.T) {
	for cond, want := range map[string]bool{
		"${host.platform} == 'linux'": true,
		other:                         true,
		idGT5:                         false,
		"${agent.id} == 'a":           false,
		"$${agent.id}":                false,
		"${a-b} == 1":                 false,
	} {
		assert.Equal(t, want, MayEvaluate(cond, self), cond)
	}
}

// FuzzNeverTrue checks that the analysis never panics and never prunes a
// condition that some concrete values of the variables make true.
func FuzzNeverTrue(f *testing.F) {
	for _, s := range []string{
		other, "${ agent.id } == 'x'", fallbackZ, "not (" + other + ")",
		"(" + other + ") and (${a} == 1)", "(" + other + ") or ${b}", "${a} > 5 and " + other,
	} {
		f.Add(s)
	}
	worlds := []map[string]any{
		{agentIDVar: self},
		{},
		{agentIDVar: self, "a": 1, "b": true, platform: linux},
		{"a": "x", "b": false, "z": "agent-2"},
		{agentIDVar: self, "a": 5.5, "b": self},
	}
	f.Fuzz(func(t *testing.T, cond string) {
		if !NeverTrue(cond, self) {
			return
		}
		n, err := parse(cond)
		require.NoError(t, err)
		for _, w := range worlds {
			ev := evaluator{vars: w}
			assert.Zero(t, ev.eval(n).topLevel()&oTrue, "%q is true for %v", cond, w)
		}
	})
}

func TestParseCacheConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 2000 {
				c := fmt.Sprintf("${agent.id} == 'agent-%d'", (i+g)%300)
				assert.Equal(t, c != pinned, NeverTrue(c, self))
			}
		})
	}
	wg.Wait()
}
