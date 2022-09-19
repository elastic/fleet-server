// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

func TestNewParsedPolicy(t *testing.T) {
	// Run two formatting of the same payload to validate that the sha2 remains the same
	payloads := []string{
		testPolicy,
		minified,
	}

	for _, payload := range payloads {
		// Load the model into the policy object
		var m model.Policy
		if err := json.Unmarshal([]byte(payload), &m); err != nil {
			t.Fatal(err)
		}

		m.Data = json.RawMessage(testPolicy)

		pp, err := NewParsedPolicy(m)
		if err != nil {
			t.Fatal(err)
		}

		fields := []string{
			"id",
			"revision",
			"outputs",
			"output_permissions",
			"agent",
			"inputs",
			"fleet",
		}

		// Validate the fields;  Expect the following top level items
		if len(pp.Fields) != len(fields) {
			t.Error("Expected N fields")
		}

		for _, f := range fields {
			if _, ok := pp.Fields[f]; !ok {
				t.Error(fmt.Sprintf("Missing field %s", f))
			}
		}

		// Now validate output perms hash
		if len(pp.Roles) != 1 {
			t.Error("Only expected one role")
		}

		// Validate that default was found
		if pp.Default.Name != "other" {
			t.Error("other output should be identified as default")
		}
		defaultOutput := pp.Outputs[pp.Default.Name]
		if defaultOutput.Role == nil {
			t.Error("other output role should be identified")
		}

		expectedSha2 := "d4d0840fe28ca4900129a749b56cee729562c0a88c935192c659252b5b0d762a"
		if defaultOutput.Role.Sha2 != expectedSha2 {
			t.Fatal(fmt.Sprintf("Expected sha2: '%s', got '%s'.", expectedSha2, defaultOutput.Role.Sha2))
		}
	}
}

func TestNewParsedPolicyNoES(t *testing.T) {
	// Load the model into the policy object
	var m model.Policy
	if err := json.Unmarshal([]byte(logstashOutputPolicy), &m); err != nil {
		t.Fatal(err)
	}

	m.Data = json.RawMessage(logstashOutputPolicy)

	pp, err := NewParsedPolicy(m)
	if err != nil {
		t.Fatal(err)
	}
	fields := []string{
		"id",
		"revision",
		"outputs",
		"agent",
		"inputs",
		"fleet",
	}

	// Validate the fields;  Expect the following top level items
	if len(pp.Fields) != len(fields) {
		t.Errorf("Expected %d fields, got %d", len(fields), len(pp.Fields))
	}

	for _, f := range fields {
		if _, ok := pp.Fields[f]; !ok {
			t.Error(fmt.Sprintf("Missing field %s", f))
		}
	}

	// Validate that default was found
	if pp.Default.Name != "remote_not_es" {
		t.Error("other output should be identified as default")
	}
}
