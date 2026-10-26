// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package eval

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/definitions"
)

func parseFlag(t *testing.T, raw string) *definitions.Flag {
	t.Helper()
	var f definitions.Flag
	require.NoError(t, json.Unmarshal([]byte(raw), &f))
	return &f
}

func lookupOf(flags ...*Flag) Lookup {
	m := make(map[string]*Flag, len(flags))
	for _, f := range flags {
		m[f.Key] = f
	}
	return func(key string) *Flag { return m[key] }
}

func mustContext(t *testing.T, raw string) Context {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &m))
	ctx, err := FlattenContext(m)
	require.NoError(t, err)
	return ctx
}

const cascadeFlag = `{
  "key": "discover.cascadeLayoutEnabled", "value_type": "boolean", "variations": [true, false],
  "apps": ["kibana"],
  "environments": {
    "qa": {
      "default": false,
      "rules": [
        { "type": "match", "attribute": "kibana.offering", "operator": "in", "values": ["serverless"],
          "rules": [
            { "type": "match", "attribute": "organization.key", "values": ["12345", 54321], "return": true },
            { "type": "match", "attribute": "kibana.project_type", "operator": "not_in", "values": ["search"],
              "rules": [{ "type": "percentage", "per_attribute": "organization.key", "percentages": { "true": 100, "false": 0 } }] }
          ] },
        { "type": "match", "attribute": "kibana.version", "operator": "semver_lt", "values": ["9.3.2"], "return": true }
      ]
    },
    "production": { "default": false }
  }
}`

func TestEvaluate(t *testing.T) {
	flag := Compile(parseFlag(t, cascadeFlag))
	require.NoError(t, flag.Err)

	testcases := map[string]struct {
		env     string
		context string
		value   any
		reason  Reason
		code    ErrorCode
	}{
		"static default": {
			env: "production", context: `{}`, value: false, reason: ReasonStatic,
		},
		"unknown environment": {
			env: "staging", context: `{}`, code: ErrorFlagNotFound,
		},
		"no rule matches": {
			env: "qa", context: `{"kibana.offering": "traditional", "kibana.version": "9.4.0"}`, value: false, reason: ReasonDefault,
		},
		"nested match, flat dotted keys": {
			env: "qa", context: `{"kibana.offering": "serverless", "organization.key": "12345"}`, value: true, reason: ReasonTargetingMatch,
		},
		"nested match, nested objects": {
			env: "qa", context: `{"kibana": {"offering": "serverless"}, "organization": {"key": "12345"}}`, value: true, reason: ReasonTargetingMatch,
		},
		"values match by string form": {
			env: "qa", context: `{"kibana.offering": "serverless", "organization.key": 54321}`, value: true, reason: ReasonTargetingMatch,
		},
		"nested AND requires the parent condition": {
			env: "qa", context: `{"kibana.offering": "traditional", "organization.key": "12345", "kibana.version": "9.4.0"}`, value: false, reason: ReasonDefault,
		},
		"nested percentage under not_in": {
			env: "qa", context: `{"kibana.offering": "serverless", "organization.key": "999", "kibana.project_type": "observability"}`, value: true, reason: ReasonSplit,
		},
		"nested rules without match fall through to the next top-level rule": {
			env: "qa", context: `{"kibana.offering": "serverless", "organization.key": "999", "kibana.project_type": "search", "kibana.version": "9.3.1"}`, value: true, reason: ReasonTargetingMatch,
		},
		"nested percentage without attribute does not match": {
			env: "qa", context: `{"kibana.offering": "serverless", "kibana.project_type": "observability"}`, value: false, reason: ReasonDefault,
		},
		"semver lt matches": {
			env: "qa", context: `{"kibana.version": "9.3.1"}`, value: true, reason: ReasonTargetingMatch,
		},
		"semver lt prerelease is lower": {
			env: "qa", context: `{"kibana.version": "9.3.2-SNAPSHOT"}`, value: true, reason: ReasonTargetingMatch,
		},
		"semver lt does not match equal": {
			env: "qa", context: `{"kibana.version": "9.3.2"}`, value: false, reason: ReasonDefault,
		},
		"semver compares numerically": {
			env: "qa", context: `{"kibana.version": "9.10.0"}`, value: false, reason: ReasonDefault,
		},
		"invalid semver does not match": {
			env: "qa", context: `{"kibana.version": "not-a-version"}`, value: false, reason: ReasonDefault,
		},
	}
	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			res := Evaluate(flag, tc.env, mustContext(t, tc.context), lookupOf(flag))
			if tc.code != "" {
				assert.Equal(t, tc.code, res.ErrorCode)
				assert.Equal(t, ReasonError, res.Reason)
				return
			}
			require.False(t, res.Failed(), res.ErrorDetails)
			assert.Equal(t, tc.value, res.Value)
			assert.Equal(t, tc.reason, res.Reason)
			assert.Equal(t, definitions.ValueKey(tc.value), res.Variant)
		})
	}
}

func TestSemverOperators(t *testing.T) {
	testcases := []struct {
		op      string
		version string
		match   bool
	}{
		{"semver_lt", "9.2.0", true},
		{"semver_lt", "9.3.0", false},
		{"semver_lte", "9.3.0", true},
		{"semver_lte", "9.3.1", false},
		{"semver_gt", "9.3.1", true},
		{"semver_gt", "9.3.0", false},
		{"semver_gte", "9.3.0", true},
		{"semver_gte", "9.2.99", false},
	}
	for _, tc := range testcases {
		t.Run(tc.op+" "+tc.version, func(t *testing.T) {
			flag := Compile(parseFlag(t, fmt.Sprintf(`{"key": "f", "variations": ["on", "off"], "apps": ["a"],
			  "environments": {"e": {"default": "off", "rules": [
			    {"type": "match", "attribute": "v", "operator": %q, "values": ["9.3.0"], "return": "on"}]}}}`, tc.op)))
			require.NoError(t, flag.Err)
			res := Evaluate(flag, "e", Context{"v": tc.version}, lookupOf(flag))
			assert.Equal(t, tc.match, res.Value == "on")
		})
	}
}

func TestPrerequisites(t *testing.T) {
	parent := Compile(parseFlag(t, `{"key": "parent", "variations": [true, false], "apps": ["a"],
	  "environments": {"e": {"default": false, "rules": [
	    {"type": "match", "attribute": "tier", "values": ["gold"], "return": true}]}}}`))
	child := Compile(parseFlag(t, `{"key": "child", "variations": ["new", "old"], "apps": ["a"],
	  "environments": {"e": {"default": "old", "prerequisites": [{"flag": "parent", "value": true}],
	    "rules": [{"type": "match", "attribute": "tier", "operator": "not_in", "values": ["none"], "return": "new"}]}}}`))
	missing := Compile(parseFlag(t, `{"key": "missing", "variations": [true, false], "apps": ["a"],
	  "environments": {"e": {"default": false, "prerequisites": [{"flag": "nope", "value": true}],
	    "rules": [{"type": "match", "attribute": "tier", "values": ["gold"], "return": true}]}}}`))
	lookup := lookupOf(parent, child, missing)

	res := Evaluate(child, "e", Context{"tier": "gold"}, lookup)
	assert.Equal(t, "new", res.Value)
	assert.Equal(t, ReasonTargetingMatch, res.Reason)

	// The rule would return "new", but the prerequisite is not met, so the flag is not served.
	res = Evaluate(child, "e", Context{"tier": "silver"}, lookup)
	assert.Equal(t, ErrorGeneral, res.ErrorCode)
	assert.Empty(t, res.Value)
	assert.Contains(t, res.ErrorDetails, "parent")

	res = Evaluate(missing, "e", Context{"tier": "gold"}, lookup)
	assert.Equal(t, ErrorGeneral, res.ErrorCode)
	assert.Empty(t, res.Value)
	assert.Contains(t, res.ErrorDetails, "nope")
}

func TestPrerequisiteCycle(t *testing.T) {
	a := Compile(parseFlag(t, `{"key": "a", "variations": [true, false], "apps": ["x"],
	  "environments": {"e": {"default": false, "prerequisites": [{"flag": "b", "value": true}]}}}`))
	b := Compile(parseFlag(t, `{"key": "b", "variations": [true, false], "apps": ["x"],
	  "environments": {"e": {"default": true, "prerequisites": [{"flag": "a", "value": false}]}}}`))
	self := Compile(parseFlag(t, `{"key": "self", "variations": [true, false], "apps": ["x"],
	  "environments": {"e": {"default": true, "prerequisites": [{"flag": "self", "value": true}]}}}`))
	lookup := lookupOf(a, b, self)

	for _, f := range []*Flag{a, b, self} {
		res := Evaluate(f, "e", Context{}, lookup)
		assert.Equal(t, ErrorGeneral, res.ErrorCode, f.Key)
		assert.Contains(t, res.ErrorDetails, "cycle")
	}
}

func TestPrerequisiteDepth(t *testing.T) {
	flags := make([]*Flag, 0, MaxPrerequisiteDepth+2)
	for i := 0; i <= MaxPrerequisiteDepth+1; i++ {
		prereq := ""
		if i <= MaxPrerequisiteDepth {
			prereq = fmt.Sprintf(`, "prerequisites": [{"flag": "f%d", "value": true}]`, i+1)
		}
		flags = append(flags, Compile(parseFlag(t, fmt.Sprintf(`{"key": "f%d", "variations": [true, false], "apps": ["x"],
		  "environments": {"e": {"default": true%s}}}`, i, prereq))))
	}
	res := Evaluate(flags[0], "e", Context{}, lookupOf(flags...))
	assert.Equal(t, ErrorGeneral, res.ErrorCode)
	assert.Contains(t, res.ErrorDetails, "deeper")

	// A chain within the limit is fine.
	res = Evaluate(flags[2], "e", Context{}, lookupOf(flags...))
	assert.False(t, res.Failed(), res.ErrorDetails)
}

func TestTargetingKeyMissing(t *testing.T) {
	flag := Compile(parseFlag(t, `{"key": "f", "variations": ["a", "b"], "apps": ["x"],
	  "environments": {"e": {"default": "a", "rules": [
	    {"type": "percentage", "per_attribute": "targetingKey", "percentages": {"a": 50, "b": 50}}]}}}`))
	require.NoError(t, flag.Err)

	res := Evaluate(flag, "e", Context{}, lookupOf(flag))
	assert.Equal(t, ErrorTargetingKeyMissing, res.ErrorCode)

	res = Evaluate(flag, "e", Context{"targetingKey": "user-1"}, lookupOf(flag))
	assert.Equal(t, ReasonSplit, res.Reason)
}

func TestCompileErrors(t *testing.T) {
	testcases := map[string]struct {
		envs string
		err  string
	}{
		"default not a variation":    {`{"e": {"default": "maybe"}}`, "default \"maybe\" is not a variation"},
		"unknown rule type":          {`{"e": {"default": true, "rules": [{"type": "weird"}]}}`, "unknown rule type"},
		"unknown operator":           {`{"e": {"default": true, "rules": [{"type": "match", "attribute": "a", "operator": "eq", "values": [1], "return": true}]}}`, "unknown operator"},
		"match without values":       {`{"e": {"default": true, "rules": [{"type": "match", "attribute": "a", "return": true}]}}`, "without values"},
		"match without return/rules": {`{"e": {"default": true, "rules": [{"type": "match", "attribute": "a", "values": [1]}]}}`, "either return or rules"},
		"return not a variation":     {`{"e": {"default": true, "rules": [{"type": "match", "attribute": "a", "values": [1], "return": "x"}]}}`, "return \"x\" is not a variation"},
		"invalid semver value":       {`{"e": {"default": true, "rules": [{"type": "match", "attribute": "a", "operator": "semver_lt", "values": ["x.y"], "return": true}]}}`, "invalid semver"},
		"percentages do not sum":     {`{"e": {"default": true, "rules": [{"type": "percentage", "per_attribute": "a", "percentages": {"true": 10, "false": 80}}]}}`, "sum to 100"},
		"percentage unknown key":     {`{"e": {"default": true, "rules": [{"type": "percentage", "per_attribute": "a", "percentages": {"yes": 100}}]}}`, "not a variation"},
		"nested invalid rule":        {`{"e": {"default": true, "rules": [{"type": "match", "attribute": "a", "values": [1], "rules": [{"type": "percentage", "percentages": {"true": 100}}]}]}}`, "rules[0]: rules[0]: percentage rule without per_attribute"},
	}
	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			flag := Compile(parseFlag(t, `{"key": "f", "variations": [true, false], "apps": ["x"], "environments": `+tc.envs+`}`))
			require.Error(t, flag.Err)
			assert.Contains(t, flag.Err.Error(), tc.err)
			assert.True(t, flag.AssignedTo("x"))
			assert.True(t, flag.HasEnvironment("e"))

			res := Evaluate(flag, "e", Context{}, lookupOf(flag))
			assert.Equal(t, ErrorParse, res.ErrorCode)
		})
	}
}

func TestFlattenContext(t *testing.T) {
	ctx, err := FlattenContext(map[string]any{
		"targetingKey":     "user-1",
		"kibana":           map[string]any{"version": "9.3.0", "build": map[string]any{"number": float64(1)}},
		"organization.key": "123",
		"tags":             []any{"a", "b"},
		"ignored":          nil,
	})
	require.NoError(t, err)
	assert.Equal(t, Context{
		"targetingKey":        "user-1",
		"kibana.version":      "9.3.0",
		"kibana.build.number": float64(1),
		"organization.key":    "123",
		"tags":                []any{"a", "b"},
	}, ctx)
	assert.Equal(t, "user-1", ctx.TargetingKey())

	_, err = FlattenContext(map[string]any{"a.b": "x", "a": map[string]any{"b": "y"}})
	require.ErrorContains(t, err, "more than once")

	_, err = FlattenContext(map[string]any{"targetingKey": float64(1)})
	require.ErrorContains(t, err, "targetingKey must be a string")

	_, err = FlattenContext(map[string]any{"list": []any{map[string]any{"a": 1}}})
	require.ErrorContains(t, err, "list of scalar")
}

func TestListAttributes(t *testing.T) {
	flag := Compile(parseFlag(t, `{"key": "f", "variations": [true, false], "apps": ["x"],
	  "environments": {"e": {"default": false, "rules": [
	    {"type": "match", "attribute": "roles", "values": ["admin"], "return": true}]}}}`))
	require.NoError(t, flag.Err)
	assert.Equal(t, true, Evaluate(flag, "e", Context{"roles": []any{"viewer", "admin"}}, lookupOf(flag)).Value)
	assert.Equal(t, false, Evaluate(flag, "e", Context{"roles": []any{"viewer"}}, lookupOf(flag)).Value)
}

func TestIsEnabledByPercentage(t *testing.T) {
	assert.False(t, IsEnabledByPercentage("k", "flag", 0))
	assert.False(t, IsEnabledByPercentage("k", "flag", -5))
	assert.True(t, IsEnabledByPercentage("k", "flag", 100))
	assert.True(t, IsEnabledByPercentage("k", "flag", 150))

	// Stable across calls and consistent with Bucket.
	for i := range 200 {
		key := fmt.Sprintf("org-%d", i)
		b := Bucket(key, "flag")
		require.GreaterOrEqual(t, b, 0)
		require.Less(t, b, 100)
		assert.Equal(t, b < 30, IsEnabledByPercentage(key, "flag", 30))
		assert.Equal(t, b, Bucket(key, "flag"))
	}
}

func TestPercentageDistribution(t *testing.T) {
	flag := Compile(parseFlag(t, `{"key": "rollout", "variations": ["red", "blue", "green"], "apps": ["x"],
	  "environments": {"e": {"default": "red", "rules": [
	    {"type": "percentage", "per_attribute": "organization.key", "percentages": {"red": 10, "blue": 40, "green": 50}}]}}}`))
	require.NoError(t, flag.Err)

	const n = 20000
	counts := map[any]int{}
	for i := range n {
		key := fmt.Sprintf("org-%d", i)
		res := Evaluate(flag, "e", Context{"organization.key": key}, lookupOf(flag))
		require.Equal(t, ReasonSplit, res.Reason)
		counts[res.Value]++

		// The first variation agrees with IsEnabledByPercentage on its own weight.
		assert.Equal(t, IsEnabledByPercentage(key, "rollout", 10), res.Value == "red")
	}
	const tolerance = 0.02
	assert.InDelta(t, 0.10, float64(counts["red"])/n, tolerance)
	assert.InDelta(t, 0.40, float64(counts["blue"])/n, tolerance)
	assert.InDelta(t, 0.50, float64(counts["green"])/n, tolerance)
}

func TestPercentageIsStablePerKeyAndVariesPerFlag(t *testing.T) {
	differs := false
	for i := range 100 {
		key := fmt.Sprintf("org-%d", i)
		if Bucket(key, "flag-a") != Bucket(key, "flag-b") {
			differs = true
			break
		}
	}
	assert.True(t, differs, "buckets should depend on the flag key")
}
