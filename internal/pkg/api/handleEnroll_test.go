// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"reflect"
	"testing"
)

func TestRemoveDuplicateStr(t *testing.T) {
	tests := []struct {
		name      string
		inputTags []string
		agentTags []string
	}{
		{
			name:      "empty array",
			inputTags: []string{},
			agentTags: []string{},
		},
		{
			name:      "one duplicated tag",
			inputTags: []string{"foo", "foo", "foo", "foo"},
			agentTags: []string{"foo"},
		},
		{
			name:      "multiple duplicated tags",
			inputTags: []string{"foo", "bar", "bar", "baz", "foo"},
			agentTags: []string{"bar", "baz", "foo"},
		},
	}
	for _, tr := range tests {
		t.Run(tr.name, func(t *testing.T) {
			uniqueTags := removeDuplicateStr(tr.inputTags)
			if !reflect.DeepEqual(uniqueTags, tr.agentTags) {
				t.Fatalf("failed to remove tag duplicates from %v: expected %v, found %v", tr.inputTags, uniqueTags, tr.agentTags)
			}
		})
	}
}
