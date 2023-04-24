// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

// Test json encoding/decoding for all req/resp items
import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAckRequest(t *testing.T) {
	ar := AckRequest{}
	err := json.Unmarshal([]byte(`{
	"events": [{
	    "action_id": "test-action-1",
	    "action_input_type": "input-type-1",
	    "agent_id": "test-agent-1",
	    "completed_at": "time-1",
	    "message": "event-message",
	    "policy_id": "policy-1",
	    "started_at": "time-2",
	    "stream_id": "stream-1",
	    "subtype": "ACKNOWLEDGED",
	    "timestamp": "time-3",
	    "type": "ACTION_RESULT"
	}, {
	    "action_data": {"key1": "value1"},
	    "action_id": "test-action-2",
	    "action_input_type": "input-type-2",
	    "action_response": {"key2": "value2"},
	    "agent_id": "test-agent-2",
	    "completed_at": "time-4",
	    "data": {"key3": "value3"},
	    "error": "error-1",
	    "message": "event-message",
	    "payload": {"key3": "value3"},
	    "policy_id": "policy-2",
	    "started_at": "time-5",
	    "stream_id": "stream-2",
	    "subtype": "ACKNOWLEDGED",
	    "timestamp": "time-6",
	    "type": "ACTION_RESULT"
	}]
    }`), &ar)
	require.NoError(t, err)
	assert.Len(t, ar.Events, 2)

	ev := ar.Events[0]
	assert.Nil(t, ev.ActionData)
	assert.Equal(t, "test-action-1", ev.ActionId)
	assert.Equal(t, "input-type-1", ev.ActionInputType)
	assert.Nil(t, ev.ActionResponse)
	assert.Equal(t, "test-agent-1", ev.AgentId)
	assert.Equal(t, "time-1", ev.CompletedAt)
	assert.Nil(t, ev.Data)
	assert.Nil(t, ev.Error)
	assert.Equal(t, "event-message", ev.Message)
	assert.Nil(t, ev.Payload)
	assert.Equal(t, "policy-1", ev.PolicyId)
	assert.Equal(t, "time-2", ev.StartedAt)
	assert.Equal(t, "stream-1", ev.StreamId)
	assert.Equal(t, ACKNOWLEDGED, ev.Subtype)
	assert.Equal(t, "time-3", ev.Timestamp)
	assert.Equal(t, ACTIONRESULT, ev.Type)

	ev = ar.Events[1]
	assert.NotNil(t, ev.ActionData)
	assert.Equal(t, "test-action-2", ev.ActionId)
	assert.Equal(t, "input-type-2", ev.ActionInputType)
	assert.NotNil(t, ev.ActionResponse)
	assert.Equal(t, "test-agent-2", ev.AgentId)
	assert.Equal(t, "time-4", ev.CompletedAt)
	assert.NotNil(t, ev.Data)
	assert.NotNil(t, ev.Error)
	assert.Equal(t, "event-message", ev.Message)
	assert.NotNil(t, ev.Payload)
	assert.Equal(t, "policy-2", ev.PolicyId)
	assert.Equal(t, "time-5", ev.StartedAt)
	assert.Equal(t, "stream-2", ev.StreamId)
	assert.Equal(t, ACKNOWLEDGED, ev.Subtype)
	assert.Equal(t, "time-6", ev.Timestamp)
	assert.Equal(t, ACTIONRESULT, ev.Type)

	// Sanity check embedded *json.RawMessage here
	var obj map[string]interface{}
	err = json.Unmarshal(*ev.ActionData, &obj)
	require.NoError(t, err)
	v, ok := obj["key1"]
	require.True(t, ok)
	assert.Equal(t, "value1", v)

	p, err := json.Marshal(&ar)
	require.NoError(t, err)
	require.NotEmpty(t, p)
}

func TestUploadBeginRequest(t *testing.T) {
	br := UploadBeginRequest{}
	body := `{
	    "action_id": "abc123",
	    "agent_id": "def456",
	    "file": {
		"mime_type": "text",
		"name": "fname",
		"size": 100,
		"key1": "val1"
	    },
	    "src": "agent",
	    "key2": "val2"
	}`
	err := json.Unmarshal([]byte(body), &br)
	require.NoError(t, err)

	assert.Equal(t, "abc123", br.ActionId)
	assert.Equal(t, "def456", br.AgentId)
	assert.Equal(t, "text", br.File.MimeType)
	assert.Equal(t, "fname", br.File.Name)
	assert.Equal(t, int64(100), br.File.Size)
	v, ok := br.File.Get("key1")
	require.True(t, ok)
	assert.Equal(t, "val1", v)
	v, ok = br.Get("key2")
	require.True(t, ok)
	assert.Equal(t, "val2", v)
	_, ok = br.Get("other")
	assert.False(t, ok)

	p, err := json.Marshal(&br)
	require.NoError(t, err)
	require.NotEmpty(t, p)
}

func TestActionRespSerialization(t *testing.T) {
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
			action: Action{Id: "1234"},
		},
		{
			name:   "action signed",
			action: Action{Id: "1234", Signed: &ActionSignature{Data: "eyJAdGltZXN0YW==", Signature: "U6NOg4ssxpFV="}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			validateSerialization(t, tc.action)
		})
	}
}

func validateSerialization(t *testing.T, action Action) {
	b, err := json.Marshal(action)
	assert.NoError(t, err)

	var m map[string]interface{}
	err = json.Unmarshal(b, &m)
	assert.NoError(t, err)

	accID, ok := m["id"]

	assert.True(t, ok)
	assert.Equal(t, action.Id, accID)

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
