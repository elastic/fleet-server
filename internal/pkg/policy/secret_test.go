// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package policy

import (
	"context"
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

func TestReplaceSecretRefPartial(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "value1",
	}
	val := replaceSecretRef("partial $co.elastic.secret{abcd}", secretRefs)
	assert.Equal(t, "partial value1", val)
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

func TestGetSecretValues(t *testing.T) {
	secretRefsJSON := []SecretReference{{ID: "ref1"}, {ID: "ref2"}}
	secretRefsRaw, _ := json.Marshal(secretRefsJSON)
	bulker := ftesting.NewMockBulk()

	secretRefs, _ := getSecretValues(context.TODO(), secretRefsRaw, bulker)

	expectedRefs := map[string]string{
		"ref1": "ref1_value",
		"ref2": "ref2_value",
	}
	assert.Equal(t, expectedRefs, secretRefs)
}

func TestGetPolicyInputsWithSecretsAndStreams(t *testing.T) {
	secretRefsJSON := []SecretReference{{ID: "ref1"}, {ID: "ref2"}, {ID: "ref3"}}
	secretRefsRaw, _ := json.Marshal(secretRefsJSON)
	inputsJSON := []map[string]interface{}{
		{"id": "input1", "package_var_secret": "$co.elastic.secret{ref1}",
			"input_var_secret": "$co.elastic.secret{ref2}"},
		{"id": "input2", "streams": []map[string]interface{}{
			{
				"id":                 "stream1",
				"package_var_secret": "$co.elastic.secret{ref1}",
				"input_var_secret":   "$co.elastic.secret{ref2}",
				"stream_var_secret":  "$co.elastic.secret{ref3}",
			},
		}},
	}
	inputsRaw, _ := json.Marshal(inputsJSON)
	fields := map[string]json.RawMessage{
		"secret_references": secretRefsRaw,
		"inputs":            inputsRaw,
	}
	bulker := ftesting.NewMockBulk()
	expectedStream := map[string]interface{}{
		"id":                 "stream1",
		"package_var_secret": "ref1_value",
		"input_var_secret":   "ref2_value",
		"stream_var_secret":  "ref3_value",
	}
	expectedResult := []map[string]interface{}{
		{"id": "input1", "package_var_secret": "ref1_value",
			"input_var_secret": "ref2_value"},
		{"id": "input2", "streams": []interface{}{expectedStream}},
	}

	result, _ := getPolicyInputsWithSecrets(context.TODO(), fields, bulker)

	assert.Equal(t, expectedResult, result)
}

func TestGetPolicyInputsNoopWhenNoSecrets(t *testing.T) {
	inputsJSON := []map[string]interface{}{
		{"id": "input1"},
		{"id": "input2", "streams": []map[string]interface{}{
			{
				"id": "stream1",
			},
		}},
	}
	inputsRaw, _ := json.Marshal(inputsJSON)
	fields := map[string]json.RawMessage{
		"inputs": inputsRaw,
	}
	bulker := ftesting.NewMockBulk()
	expectedStream := map[string]interface{}{
		"id": "stream1",
	}
	expectedResult := []map[string]interface{}{
		{"id": "input1"},
		{"id": "input2", "streams": []interface{}{expectedStream}},
	}

	result, _ := getPolicyInputsWithSecrets(context.TODO(), fields, bulker)

	assert.Equal(t, expectedResult, result)
}
