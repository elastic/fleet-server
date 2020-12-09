// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package dl

import (
	"encoding/json"
	"fleet/internal/pkg/rnd"
	"testing"
)

func TestPrepareQueryAllEnrollmentAPIKeys(t *testing.T) {
	r := rnd.New()
	sz := r.Int(0, 1000)
	b, err := RenderAllEnrollmentAPIKeysQuery(uint64(sz))
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]interface{}
	err = json.Unmarshal(b, &m)
	if err != nil {
		t.Fatal(err)
	}

	const key = "size"
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing %v query property", key)
	}

	n, ok := v.(float64)
	if !ok {
		t.Fatalf("invalid %[1]v property value: %[2]v, type: %[2]T", key, v)
	}
	if n != float64(sz) {
		t.Fatalf("unexpected %v: want %v, got %v", key, sz, n)
	}
}

func TestPrepareEnrollmentAPIKeyByIDQuery(t *testing.T) {
	tmpl, err := PrepareEnrollmentAPIKeyByIDQuery()
	if err != nil {
		t.Fatal(err)
	}

	if tmpl == nil {
		t.Fatal("failed to prepare query, want non-nil")
	}
}
