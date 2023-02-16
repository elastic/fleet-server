// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActionSerialization(t *testing.T) {
	tests := []struct {
		name   string
		action Action
	}{
		{
			name:   "empty action",
			action: Action{},
		},
		{
			name:   "action id only",
			action: Action{ActionID: "1234"},
		},
		{
			name:   "action signed",
			action: Action{ActionID: "1234", Signed: &Signed{Data: "eyJAdGltZXN0YW==", Signature: "U6NOg4ssxpFV="}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			validateSerialization(t, tc.action)
		})
	}
}

func validateSerialization(t *testing.T, action Action) {
	t.Helper()

	b, err := json.Marshal(action)
	assert.NoError(t, err)

	var m map[string]interface{}
	err = json.Unmarshal(b, &m)
	assert.NoError(t, err)

	accID, ok := m["action_id"]

	if action.ActionID == "" {
		assert.False(t, ok)
	} else {
		assert.Equal(t, action.ActionID, accID)
	}

	signed, ok := m["signed"]
	if action.Signed == nil {
		assert.False(t, ok)
	} else {
		sm, ok := signed.(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, action.Signed.Data, sm["data"])
		assert.Equal(t, action.Signed.Signature, sm["signature"])
	}

}
