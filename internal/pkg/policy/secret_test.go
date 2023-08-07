// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"encoding/json"
	"testing"

	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/stretchr/testify/assert"
)

func TestReplaceSecretRef(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "value1",
	}
	val := replaceSecretRef("$co.elastic.secret{abcd}", secretRefs)
	assert.Equal(t, "value1", val)
}

func TestReplaceSecretRefNotASecret(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "value1",
	}
	val := replaceSecretRef("abcd", secretRefs)
	assert.Equal(t, "abcd", val)
}

func TestReplaceSecretRefNotFound(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "value1",
	}
	val := replaceSecretRef("$co.elastic.secret{other}", secretRefs)
	assert.Equal(t, "$co.elastic.secret{other}", val)
}

func TestGetSecretReferences(t *testing.T) {
	secretRefsJson := []SecretReference{{Id: "ref1"}, {Id: "ref2"}}
	secretRefsRaw, _ := json.Marshal(secretRefsJson)
	bulker := ftesting.NewMockBulk()

	secretRefs, _ := getSecretReferences(secretRefsRaw, bulker)

	expectedRefs := map[string]string{
		"ref1": "ref1_value",
		"ref2": "ref2_value",
	}
	assert.Equal(t, expectedRefs, secretRefs)
}
