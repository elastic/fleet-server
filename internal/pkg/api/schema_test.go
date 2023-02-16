package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActionRespSerialization(t *testing.T) {
	tests := []struct {
		name   string
		action ActionResp
	}{
		{
			name:   "empty action",
			action: ActionResp{},
		},
		{
			name:   "action id only",
			action: ActionResp{ID: "1234"},
		},
		{
			name:   "action signed",
			action: ActionResp{ID: "1234", Signed: &ActionRespSigned{Data: "eyJAdGltZXN0YW==", Signature: "U6NOg4ssxpFV="}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			validateSerialization(t, tc.action)
		})
	}
}

func validateSerialization(t *testing.T, action ActionResp) {
	t.Helper()

	b, err := json.Marshal(action)
	assert.NoError(t, err)

	var m map[string]interface{}
	err = json.Unmarshal(b, &m)
	assert.NoError(t, err)

	accID, ok := m["id"]

	assert.True(t, ok)
	assert.Equal(t, action.ID, accID)

	signed, ok := m["signed"]
	if action.Signed == nil {
		assert.False(t, ok)
	} else {
		sm := signed.(map[string]interface{})
		assert.Equal(t, action.Signed.Data, sm["data"])
		assert.Equal(t, action.Signed.Signature, sm["signature"])
	}

}
