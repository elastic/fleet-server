// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package dl

import "testing"

func TestPrepareAllAgentActionsQuery(t *testing.T) {
	tmpl, err := PrepareAllAgentActionsQuery()
	if err != nil {
		t.Error(err)
	}

	if tmpl == nil {
		t.Error("expected prepared query template")
	}
}

func TestPrepareAgentActionsQuery(t *testing.T) {
	tmpl, err := PrepareAgentActionsQuery()
	if err != nil {
		t.Error(err)
	}

	if tmpl == nil {
		t.Error("expected prepared query template")
	}
}
