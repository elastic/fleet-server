// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package smap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	tests := map[string]struct {
		input    Map
		keyPath  string
		expected any
	}{
		"a": {
			input:    Map{"a": 1},
			keyPath:  "a",
			expected: 1,
		},
		"a.b": {
			input:    Map{"a": Map{"b": 2}},
			keyPath:  "a.b",
			expected: 2,
		},
		"a.1": {
			input:    Map{"a": []any{10, 20, 30}},
			keyPath:  "a.1",
			expected: 20,
		},
		"a.b.2.c": {
			input:    Map{"a": Map{"b": []any{1, "b", map[string]any{"c": 3}}}},
			keyPath:  "a.b.2.c",
			expected: 3,
		},
		"nonexistent": {
			input:    Map{"a": 1},
			keyPath:  "b",
			expected: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := tc.input.Get(tc.keyPath)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestSet(t *testing.T) {
	tests := map[string]struct {
		input       Map
		keyPath     string
		value       any
		expected    Map
		expectedErr string
	}{
		"a": {
			input:    Map{"a": 1},
			keyPath:  "b",
			value:    42,
			expected: Map{"a": 1, "b": 42},
		},
		"a.c": {
			input:    Map{"a": Map{"b": map[string]any{"d": 1}}},
			keyPath:  "a.c",
			value:    42,
			expected: Map{"a": Map{"b": map[string]any{"d": 1}, "c": 42}},
		},
		"a.1": {
			input:    Map{"a": []any{10, 20, 30}},
			keyPath:  "a.1",
			value:    42,
			expected: Map{"a": []any{10, 42, 30}},
		},
		"a.3": {
			input:       Map{"a": []any{10, 20, 30}},
			keyPath:     "a.3",
			value:       42,
			expected:    Map{"a": []any{10, 20, 30}}, // No change, index out of bounds
			expectedErr: "index out of bounds at a: 3",
		},
		"a.b.2.c": {
			input:    Map{"a": Map{"b": []any{1, "b", map[string]any{"c": 3}}}},
			keyPath:  "a.b.2.c",
			value:    42,
			expected: Map{"a": Map{"b": []any{1, "b", map[string]any{"c": 42}}}},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.input.Set(tc.keyPath, tc.value)
			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.Equal(t, tc.expectedErr, err.Error())
			}
			require.Equal(t, tc.expected, tc.input)
		})
	}
}
