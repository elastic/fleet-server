// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"encoding/json"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// sameBacking reports whether two strings point at the same bytes.
func sameBacking(a, b string) bool {
	return unsafe.StringData(a) == unsafe.StringData(b)
}

// at follows a path of map keys through nested decoded JSON.
func at(t *testing.T, v any, path ...string) any {
	t.Helper()
	for _, key := range path {
		m, ok := v.(map[string]any)
		require.Truef(t, ok, "expected a map at %q, got %T", key, v)
		v = m[key]
	}
	return v
}

func stringAt(t *testing.T, v any, path ...string) string {
	t.Helper()
	s, ok := at(t, v, path...).(string)
	require.True(t, ok, "expected a string at %v", path)
	return s
}

func listAt(t *testing.T, v any, path ...string) []any {
	t.Helper()
	l, ok := at(t, v, path...).([]any)
	require.True(t, ok, "expected a list at %v", path)
	return l
}

// testPolicy builds a policy with freshly allocated copies of every string, as decoding would.
func testPolicy(query string) model.Policy {
	return model.Policy{
		PolicyID: "policy-1",
		Data: &model.PolicyData{
			Agent: map[string]any{
				"download": map[string]any{"sourceURI": strings.Clone("https://artifacts.example.test/downloads/" + strings.Repeat("x", 40))},
			},
			Inputs: []map[string]any{{
				testType: strings.Clone(benchOsquery),
				benchOsquery: map[string]any{
					testPacks: map[string]any{
						testPack: map[string]any{
							testQueries: map[string]any{
								"q1": map[string]any{
									"query":     strings.Clone(query),
									"interval":  float64(3600),
									"platforms": []any{strings.Clone("linux"), strings.Clone("darwin")},
								},
							},
						},
					},
				},
			}},
			Outputs: map[string]map[string]any{
				benchOutput: {testType: strings.Clone(benchES)},
			},
		},
	}
}

const (
	testType    = "type"
	testPacks   = "packs"
	testPack    = "pack-1"
	testQueries = "queries"
)

var queryPath = []string{benchOsquery, testPacks, testPack, testQueries, "q1"}

func queryOf(t *testing.T, p model.Policy) string {
	t.Helper()
	return stringAt(t, p.Data.Inputs[0], append(queryPath, "query")...)
}

func TestShareStrings(t *testing.T) {
	long := strings.Repeat("SELECT name, path FROM processes WHERE ", 20)
	policies := []model.Policy{testPolicy(long), testPolicy(long), {PolicyID: "no-data"}}

	before := make([][]byte, len(policies))
	for i := range policies {
		var err error
		before[i], err = json.Marshal(policies[i])
		require.NoError(t, err)
	}
	require.False(t, sameBacking(queryOf(t, policies[0]), queryOf(t, policies[1])), "precondition: strings start unshared")

	ShareStrings(policies)

	t.Run("content is unchanged", func(t *testing.T) {
		for i := range policies {
			after, err := json.Marshal(policies[i])
			require.NoError(t, err)
			assert.JSONEq(t, string(before[i]), string(after))
		}
	})

	t.Run("long equal values share memory", func(t *testing.T) {
		assert.True(t, sameBacking(queryOf(t, policies[0]), queryOf(t, policies[1])))

		a := stringAt(t, policies[0].Data.Agent, "download", "sourceURI")
		b := stringAt(t, policies[1].Data.Agent, "download", "sourceURI")
		assert.True(t, sameBacking(a, b))
	})

	t.Run("short values are left alone", func(t *testing.T) {
		la := listAt(t, policies[0].Data.Inputs[0], append(queryPath, "platforms")...)
		lb := listAt(t, policies[1].Data.Inputs[0], append(queryPath, "platforms")...)
		require.Len(t, la, 2)
		require.Len(t, lb, 2)
		for i := range la {
			sa, okA := la[i].(string)
			sb, okB := lb[i].(string)
			require.True(t, okA && okB)
			assert.False(t, sameBacking(sa, sb), "strings below minSharedLen are not tracked")
		}
	})

	t.Run("maps stay independent", func(t *testing.T) {
		download, ok := at(t, policies[0].Data.Agent, "download").(map[string]any)
		require.True(t, ok)
		download["sourceURI"] = "changed"
		assert.NotEqual(t, "changed", stringAt(t, policies[1].Data.Agent, "download", "sourceURI"))
	})

	t.Run("policy without data is untouched", func(t *testing.T) {
		assert.Nil(t, policies[2].Data)
	})
}

func TestShareStringsCap(t *testing.T) {
	oldMax := maxSharedStrings
	maxSharedStrings = 1
	t.Cleanup(func() { maxSharedStrings = oldMax })

	const key = "value"
	first := strings.Repeat("a", minSharedLen)
	second := strings.Repeat("b", minSharedLen)
	// Each string sits in its own input. shareStrings visits inputs in slice order, whereas the
	// order of keys within one map is unspecified, so this makes the test deterministic: "first"
	// always takes the only table slot before "second" is seen.
	policy := func() model.Policy {
		return model.Policy{Data: &model.PolicyData{Inputs: []map[string]any{
			{key: strings.Clone(first)},
			{key: strings.Clone(second)},
		}}}
	}
	policies := []model.Policy{policy(), policy()}

	ShareStrings(policies)

	valueOf := func(p model.Policy, input int) string {
		return stringAt(t, p.Data.Inputs[input], key)
	}
	assert.True(t, sameBacking(valueOf(policies[0], 0), valueOf(policies[1], 0)),
		"a string tracked before the cap was reached is still shared")
	assert.False(t, sameBacking(valueOf(policies[0], 1), valueOf(policies[1], 1)),
		"a new string is not tracked once the cap is reached")
	assert.Equal(t, second, valueOf(policies[1], 1), "content is unchanged either way")
}

func TestShareStringsNilSections(t *testing.T) {
	policies := []model.Policy{{Data: &model.PolicyData{}}}
	require.NotPanics(t, func() { ShareStrings(policies) })
	assert.Nil(t, policies[0].Data.Agent)
	assert.Nil(t, policies[0].Data.Inputs)
	assert.Nil(t, policies[0].Data.Outputs)
}
