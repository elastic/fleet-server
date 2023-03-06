// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package gc

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIsIntervalStringValid(t *testing.T) {
	tests := []struct {
		interval string
		expected bool
	}{
		{"", false},
		{"-3d", false},
		{"- 3 d", false},
		{" -5d", false},
		{"2-3d", false},
		{"now-5d", false},
		{"-d", false},
		{"1y", true},
		{"2M", true},
		{"4w", true},
		{"3d", true},
		{"7h", true},
		{"5H", true},
		{"6m", true},
		{"8s", true},
	}

	for _, tc := range tests {
		t.Run(tc.interval, func(t *testing.T) {
			valid := isIntervalStringValid(tc.interval)
			diff := cmp.Diff(tc.expected, valid)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}
