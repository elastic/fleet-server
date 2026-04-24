// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelFromHash_Format(t *testing.T) {
	// A valid 64-char hex hash must produce "adjective-noun".
	hash, err := hashConfigBody([]byte("receivers:\n  otlp: {}\n"))
	require.NoError(t, err)

	label := LabelFromHash(hash)
	require.NotEmpty(t, label)

	parts := strings.SplitN(label, "-", 2)
	require.Len(t, parts, 2, "label must be adjective-noun separated by a hyphen")
	assert.NotEmpty(t, parts[0], "adjective must not be empty")
	assert.NotEmpty(t, parts[1], "noun must not be empty")
}

func TestLabelFromHash_Deterministic(t *testing.T) {
	hash := "aabbccdd" + strings.Repeat("00", 28) // 64-char hex
	assert.Equal(t, LabelFromHash(hash), LabelFromHash(hash))
}

func TestLabelFromHash_DifferentBytesGiveDifferentLabels(t *testing.T) {
	// Changing the first two bytes must change the label.
	hashA := "0000" + strings.Repeat("ff", 30)
	hashB := "0100" + strings.Repeat("ff", 30)
	assert.NotEqual(t, LabelFromHash(hashA), LabelFromHash(hashB))
}

func TestLabelFromHash_SameLabelForSameTopology(t *testing.T) {
	// Same topology → same hash → same label.
	h1, err := hashConfigBody([]byte(baseTopologyConfig))
	require.NoError(t, err)
	h2, err := hashConfigBody([]byte(baseTopologyConfig))
	require.NoError(t, err)
	assert.Equal(t, LabelFromHash(h1), LabelFromHash(h2))
}

func TestLabelFromHash_EmptyInput(t *testing.T) {
	assert.Empty(t, LabelFromHash(""))
	assert.Empty(t, LabelFromHash("ab")) // too short
}

func TestLabelFromHash_InvalidHex(t *testing.T) {
	assert.Empty(t, LabelFromHash("zzzz"+strings.Repeat("00", 30)))
}

func TestWordlistsHave256UniqueEntries(t *testing.T) {
	assert.Len(t, slices.Compact(slices.Sort(labelAdjectives)), 256, "labelAdjectives contains duplicate entry")
	assert.Len(t, slices.Compact(slices.Sort(labelNounts)), 256, "labelNouns contains duplicate entry")
}
