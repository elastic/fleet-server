// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareAgentFindByEnrollmentID(t *testing.T) {

	tmpl := prepareAgentFindByEnrollmentID()
	query, _ := tmpl.RenderOne(FieldEnrollmentID, "1")
	assert.Equal(t, `{"query":{"bool":{"filter":[{"term":{"enrollment_id":"1"}}]}},"version":true}`, string(query[:]))
}
