// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package model

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAgentGetNewVersion(t *testing.T) {
	tests := []struct {
		Name    string
		Agent   *Agent
		Ver     string
		WantVer string
	}{
		{
			Name: "nil",
		},
		{
			Name:  "agent no meta empty version",
			Agent: &Agent{},
		},
		{
			Name:    "agent no meta nonempty version",
			Agent:   &Agent{},
			Ver:     "7.14",
			WantVer: "7.14",
		},
		{
			Name: "agent with meta empty new version",
			Agent: &Agent{
				Agent: &AgentMetadata{
					Version: "7.14",
				},
			},
			Ver:     "",
			WantVer: "",
		},
		{
			Name: "agent with meta empty version",
			Agent: &Agent{
				Agent: &AgentMetadata{
					Version: "",
				},
			},
			Ver:     "7.15",
			WantVer: "7.15",
		},
		{
			Name: "agent with meta non empty version",
			Agent: &Agent{
				Agent: &AgentMetadata{
					Version: "7.14",
				},
			},
			Ver:     "7.14",
			WantVer: "",
		},
		{
			Name: "agent with meta new version",
			Agent: &Agent{
				Agent: &AgentMetadata{
					Version: "7.14",
				},
			},
			Ver:     "7.15",
			WantVer: "7.15",
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			newVer := tc.Agent.CheckDifferentVersion(tc.Ver)
			diff := cmp.Diff(tc.WantVer, newVer)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}
