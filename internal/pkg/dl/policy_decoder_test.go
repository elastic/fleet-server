// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// sameBacking reports whether two strings point at the same bytes.
func sameBacking(a, b string) bool {
	return unsafe.StringData(a) == unsafe.StringData(b)
}

func policySource(inputs string) []byte {
	return fmt.Appendf(nil, `{"policy_id":"p","revision_idx":3,"@timestamp":"2026-01-01T00:00:00Z","namespaces":["a"],`+
		`"data":{"id":"p","revision":3,"outputs":{"o":{"type":"elasticsearch","hosts":["h"]}},"agent":{"x":{"y":1}},"inputs":%s}}`, inputs)
}

func decodeBoth(t *testing.T, src []byte) (std, got model.Policy, stdErr, gotErr error) {
	t.Helper()
	hit := es.HitT{ID: "id", SeqNo: 5, Version: 2, Source: src}
	stdErr = hit.Unmarshal(&std)
	gotErr = NewPolicyDecoder().Decode(hit, &got)
	return std, got, stdErr, gotErr
}

func TestPolicyDecoderMatchesEncodingJSON(t *testing.T) {
	long := strings.Repeat("SELECT 1 FROM t WHERE ", 5)
	cases := map[string]string{
		"empty array":        `[]`,
		"null inputs":        literalNull,
		"null element":       `[null,{"a":1}]`,
		"empty objects":      `[{},{"a":{}},{"a":[]}]`,
		"nested":             `[{"a":{"b":[1,2,{"c":[true,false,null]}]}}]`,
		"numbers":            `[{"a":0,"b":-0,"c":1e3,"d":1.5E-2,"e":12345678901234567890,"f":-1.25,"g":0.1}]`,
		"escapes":            `[{"a":"line\nbreak\ttab \"quoted\" back\\slash \/ slash","k\u00e9y":"v"}]`,
		"unicode escapes":    `[{"a":"caf\u00e9 \u4e16\u754c","b":"emoji \ud83d\ude00","c":"lone \ud800 surrogate"}]`,
		"raw utf8":           `[{"a":"héllo wörld 世界"}]`,
		"duplicate keys":     `[{"a":1,"a":2}]`,
		"whitespace":         " [ { \"a\" : [ 1 , 2 ] , \"b\" : \"x\" } , null ] ",
		"long duplicated":    fmt.Sprintf(`[{"q":%q},{"q":%q,"r":{"q":%q}}]`, long, long, long),
		"long with escape":   fmt.Sprintf(`[{"q":%q}]`, long+`\n`+long),
		"invalid utf8 value": "[{\"a\":\"bad \xff\xfe bytes " + strings.Repeat("x", 70) + "\"}]",
		"invalid utf8 key":   "[{\"b\xffd\":1}]",
		"control escapes":    `[{"a":"\u0000\u001f\b\f\r"}]`,
		"deep":               strings.Repeat(`[`, 50) + strings.Repeat(`]`, 50),
	}
	for name, inputs := range cases {
		t.Run(name, func(t *testing.T) {
			std, got, stdErr, gotErr := decodeBoth(t, policySource(inputs))
			require.Equal(t, stdErr == nil, gotErr == nil, "std=%v got=%v", stdErr, gotErr)
			if stdErr != nil {
				return
			}
			assert.True(t, reflect.DeepEqual(std, got), "decoded policies differ:\nstd=%#v\ngot=%#v", std, got)
		})
	}
}

func TestPolicyDecoderSharesAcrossDocuments(t *testing.T) {
	long := strings.Repeat("SELECT name FROM processes WHERE ", 4)
	inputs := fmt.Sprintf(`[{"query":%q,"short":"abc"}]`, long)
	dec := NewPolicyDecoder()
	var a, b model.Policy
	require.NoError(t, dec.Decode(es.HitT{Source: policySource(inputs)}, &a))
	require.NoError(t, dec.Decode(es.HitT{Source: policySource(inputs)}, &b))

	qa, okA := a.Data.Inputs[0]["query"].(string)
	qb, okB := b.Data.Inputs[0]["query"].(string)
	require.True(t, okA && okB)
	assert.True(t, sameBacking(qa, qb), "long equal values are shared")
	sa, okA := a.Data.Inputs[0]["short"].(string)
	sb, okB := b.Data.Inputs[0]["short"].(string)
	require.True(t, okA && okB)
	assert.False(t, sameBacking(sa, sb), "short values are not tracked")
}

func TestPolicyDecoderCap(t *testing.T) {
	oldMax := maxSharedStrings
	maxSharedStrings = 1
	t.Cleanup(func() { maxSharedStrings = oldMax })

	first := strings.Repeat("a", minSharedLen)
	second := strings.Repeat("b", minSharedLen)
	// The parser reads a document front to back, so "first" always takes the only table slot
	// before "second" is seen.
	inputs := fmt.Sprintf(`[{"first":%q,"second":%q}]`, first, second)

	dec := NewPolicyDecoder()
	var a, b model.Policy
	require.NoError(t, dec.Decode(es.HitT{Source: policySource(inputs)}, &a))
	require.NoError(t, dec.Decode(es.HitT{Source: policySource(inputs)}, &b))

	valueOf := func(p model.Policy, key string) string {
		v, ok := p.Data.Inputs[0][key].(string)
		require.True(t, ok)
		return v
	}
	assert.True(t, sameBacking(valueOf(a, "first"), valueOf(b, "first")), "a string tracked before the cap was reached is still shared")
	assert.False(t, sameBacking(valueOf(a, "second"), valueOf(b, "second")), "a new string is not tracked once the cap is reached")
	assert.Equal(t, second, valueOf(b, "second"), "content is unchanged either way")
}

func FuzzPolicyDecoderInputs(f *testing.F) {
	for _, s := range []string{`[]`, `null`, `[{"a":"x"}]`, `[null]`, `[{"a":[1,2.5,"s",null,true,{"b":{}}]}]`, `[{"a":"\u00e9\n"}]`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, inputs string) {
		src := policySource(inputs)
		hit := es.HitT{Source: src}
		var std, got model.Policy
		stdErr := hit.Unmarshal(&std)
		gotErr := NewPolicyDecoder().Decode(hit, &got)
		if (stdErr == nil) != (gotErr == nil) {
			t.Fatalf("error mismatch for %q: std=%v got=%v", inputs, stdErr, gotErr)
		}
		if stdErr == nil && !reflect.DeepEqual(std, got) {
			t.Fatalf("decoded policies differ for %q:\nstd=%#v\ngot=%#v", inputs, std, got)
		}
	})
}
