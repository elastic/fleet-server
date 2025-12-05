// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package secret

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceStringRef(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "value1",
	}
	val, replaced := replaceStringRef("$co.elastic.secret{abcd}", secretRefs)
	assert.Equal(t, "value1", val)
	assert.True(t, replaced)
}

func TestReplaceStringRefPartial(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "value1",
	}
	val, replaced := replaceStringRef("partial $co.elastic.secret{abcd}", secretRefs)
	assert.Equal(t, "partial value1", val)
	assert.True(t, replaced)
}

func TestReplaceStringRefPartial2(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "http://localhost",
	}
	val, replaced := replaceStringRef("$co.elastic.secret{abcd}/services", secretRefs)
	assert.Equal(t, "http://localhost/services", val)
	assert.True(t, replaced)
}

func TestReplaceStringRefMultiple(t *testing.T) {
	secretRefs := map[string]string{
		"secret1": "value1",
		"secret2": "value2",
	}
	val, replaced := replaceStringRef("partial \"$co.elastic.secret{secret1}\" \"$co.elastic.secret{secret2}\"", secretRefs)
	assert.Equal(t, "partial \"value1\" \"value2\"", val)
	assert.True(t, replaced)
}

func TestReplaceStringRefMultipleOneNotFound(t *testing.T) {
	secretRefs := map[string]string{
		"secret2": "value2",
	}
	val, replaced := replaceStringRef("partial \"$co.elastic.secret{secret1}\" \"$co.elastic.secret{secret2}\"", secretRefs)
	assert.Equal(t, "partial \"$co.elastic.secret{secret1}\" \"$co.elastic.secret{secret2}\"", val)
	assert.False(t, replaced)
}

func TestReplaceStringRefNotASecret(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "value1",
	}
	val, replaced := replaceStringRef("abcd", secretRefs)
	assert.Equal(t, "abcd", val)
	assert.False(t, replaced)
}

func TestReplaceStringRefNotFound(t *testing.T) {
	secretRefs := map[string]string{
		"abcd": "value1",
	}
	val, replaced := replaceStringRef("$co.elastic.secret{other}", secretRefs)
	assert.Equal(t, "$co.elastic.secret{other}", val)
	assert.False(t, replaced)
}

func TestGetSecretValues(t *testing.T) {
	refs := []model.SecretReferencesItems{{ID: "ref1"}, {ID: "ref2"}}
	bulker := ftesting.NewMockBulk()

	secretRefs, _ := GetSecretValues(context.TODO(), refs, bulker)

	expectedRefs := map[string]string{
		"ref1": "ref1_value",
		"ref2": "ref2_value",
	}
	assert.Equal(t, expectedRefs, secretRefs)
}

func TestGetActionDataWithSecrets(t *testing.T) {
	refs := []model.SecretReferencesItems{
		{ID: "ref1"},
		{ID: "ref2"},
	}
	// Input JSON with secret references
	input := map[string]interface{}{
		"username": "user1",
		"password": "$co.elastic.secret{ref1}",
		"nested": map[string]interface{}{
			"token": "$co.elastic.secret{ref2}",
		},
	}
	b, err := json.Marshal(input)
	require.NoError(t, err)

	bulker := ftesting.NewMockBulk()
	result, err := GetActionDataWithSecrets(t.Context(), b, refs, bulker)
	require.NoError(t, err)

	var out map[string]interface{}
	err = json.Unmarshal(result, &out)
	require.NoError(t, err)

	assert.Equal(t, "user1", out["username"])
	assert.Equal(t, "ref1_value", out["password"])

	nestedMap, ok := out["nested"].(map[string]interface{})
	assert.True(t, ok)

	require.NoError(t, err)
	assert.Equal(t, "ref2_value", nestedMap["token"])
}

func TestGetPolicyInputsWithSecretsAndStreams(t *testing.T) {
	refs := []model.SecretReferencesItems{{ID: "ref1"}, {ID: "ref2"}, {ID: "ref3"}}
	inputs := []map[string]interface{}{
		{"id": "input1", "package_var_secret": "$co.elastic.secret{ref1}",
			"input_var_secret": "$co.elastic.secret{ref2}"},
		{"id": "input2", "streams": []interface{}{
			map[string]interface{}{
				"id":                 "stream1",
				"package_var_secret": "$co.elastic.secret{ref1}",
				"input_var_secret":   "$co.elastic.secret{ref2}",
				"stream_var_secret":  "$co.elastic.secret{ref3}",
			},
		}},
	}
	pData := model.PolicyData{
		SecretReferences: refs,
		Inputs:           inputs,
	}
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

	secretValues := map[string]string{
		"ref1": "ref1_value",
		"ref2": "ref2_value",
		"ref3": "ref3_value",
	}
	result, keys := ProcessInputsSecrets(&pData, secretValues)

	assert.Equal(t, expectedResult, result)
	assert.ElementsMatch(t, []string{"inputs.0.package_var_secret", "inputs.0.input_var_secret", "inputs.1.streams.0.package_var_secret", "inputs.1.streams.0.input_var_secret", "inputs.1.streams.0.stream_var_secret"}, keys)
}

func TestPolicyInputSteamsEmbedded(t *testing.T) {
	refs := []model.SecretReferencesItems{{ID: "ref1"}}
	inputs := []map[string]interface{}{
		{"id": "input1", "streams": []interface{}{
			map[string]interface{}{
				"id":  "stream1",
				"key": "val",
				"embedded": map[string]interface{}{
					"embedded-key": "embedded-val",
					"embedded-arr": []interface{}{
						map[string]interface{}{
							"embedded-secret": "$co.elastic.secret{ref1}",
						},
					}},
			},
		}},
	}

	pData := model.PolicyData{
		SecretReferences: refs,
		Inputs:           inputs,
	}
	expected := []map[string]interface{}{{
		"id": "input1",
		"streams": []interface{}{
			map[string]interface{}{
				"id":  "stream1",
				"key": "val",
				"embedded": map[string]interface{}{
					"embedded-key": "embedded-val",
					"embedded-arr": []interface{}{
						map[string]interface{}{
							"embedded-secret": "ref1_value",
						},
					}},
			},
		}},
	}

	secretValues := map[string]string{
		"ref1": "ref1_value",
	}
	result, keys := ProcessInputsSecrets(&pData, secretValues)

	assert.Equal(t, expected, result)
	assert.ElementsMatch(t, []string{"inputs.0.streams.0.embedded.embedded-arr.0.embedded-secret"}, keys)
}

func TestGetPolicyInputsNoopWhenNoSecrets(t *testing.T) {
	inputs := []map[string]interface{}{
		{"id": "input1"},
		{"id": "input2", "streams": []interface{}{
			map[string]interface{}{
				"id": "stream1",
			},
		}},
	}
	pData := model.PolicyData{
		Inputs: inputs,
	}
	expectedStream := map[string]interface{}{
		"id": "stream1",
	}
	expectedResult := []map[string]interface{}{
		{"id": "input1"},
		{"id": "input2", "streams": []interface{}{expectedStream}},
	}

	result, keys := ProcessInputsSecrets(&pData, nil)

	assert.Equal(t, expectedResult, result)
	assert.Empty(t, keys)
}

func TestProcessOutputSecret(t *testing.T) {
	tests := []struct {
		name             string
		outputJSON       string
		expectOutputJSON string
		expectKeys       []string
	}{
		{
			name:             "Output without secrets",
			outputJSON:       `{"password": "test"}`,
			expectOutputJSON: `{"password": "test"}`,
			expectKeys:       nil,
		},
		{
			name: "Output with secrets",
			outputJSON: `{
				"secrets": {
					"password": {"id": "passwordid"}
				}
			}`,
			expectOutputJSON: `{
				"password": "passwordid_value"
			}`,
			expectKeys: []string{"password"},
		},
		{
			name: "Output with nested secrets",
			outputJSON: `{
				"secrets": {
					"ssl": { "key" : { "id": "sslkey" }	}
				}
			}`,
			expectOutputJSON: `{
				"ssl": {"key": "sslkey_value"}
			}`,
			expectKeys: []string{"ssl.key"},
		},
		{
			name: "Output with multiple secrets",
			outputJSON: `{
				"secrets": {
					"ssl": { "key" : { "id": "sslkey" }, "other": {"id": "sslother"}	}
				}
			}`,
			expectOutputJSON: `{
				"ssl": {"key": "sslkey_value", "other": "sslother_value"}
			}`,
			expectKeys: []string{"ssl.key", "ssl.other"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, err := smap.Parse([]byte(tc.outputJSON))
			assert.NoError(t, err)

			expectOutput, err := smap.Parse([]byte(tc.expectOutputJSON))
			assert.NoError(t, err)

			secretValues := map[string]string{
				"passwordid": "passwordid_value",
				"sslother":   "sslother_value",
				"sslkey":     "sslkey_value",
			}
			keys, err := ProcessOutputSecret(output, secretValues)
			assert.NoError(t, err)

			assert.Equal(t, expectOutput, output)
			assert.ElementsMatch(t, tc.expectKeys, keys)
		})
	}
}
