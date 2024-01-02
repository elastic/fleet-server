// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

// Test json encoding/decoding for all req/resp items
import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAckRequest(t *testing.T) {
	ar := AckRequest{}
	err := json.Unmarshal([]byte(`{
	"events": [{
	    "type": "ACTION_RESULT",
	    "subtype": "ACKNOWLEDGED",
	    "timestamp": "2023-10-31T12:00:00.000Z",
	    "action_id": "test-action-1",
	    "agent_id": "test-agent-1",
	    "message": "event-message"
	}, {
	    "type": "ACTION_RESULT",
	    "subtype": "ACKNOWLEDGED",
	    "timestamp": "2023-10-31T12:00:00.000Z",
	    "action_id": "test-action-2",
	    "agent_id": "test-agent-2",
	    "message": "event-message",
	    "action_input_type": "input-type-2",
	    "action_data": {"key1": "value1"},
	    "action_response": {"key2": "value2"},
	    "started_at": "2023-10-31T11:00:00.000Z",
	    "completed_at": "2023-10-31T12:00:00.000Z",
	    "error": "error-1"
	}, {
	    "type": "ACTION_RESULT",
	    "subtype": "ACKNOWLEDGED",
	    "timestamp": "2023-10-31T12:00:00.000Z",
	    "action_id": "test-action-3",
	    "agent_id": "test-agent-3",
	    "message": "event-message",
	    "payload":{"retry": true, "retry_attempt": 2},
	    "error": "error-2"
	}]
    }`), &ar)
	require.NoError(t, err)
	assert.Len(t, ar.Events, 3)
	ts, err := time.Parse(time.RFC3339, "2023-10-31T12:00:00.000Z")
	require.NoError(t, err)

	ev, err := ar.Events[0].AsGenericEvent()
	require.NoError(t, err)
	assert.Equal(t, "test-action-1", ev.ActionId)
	assert.Equal(t, "test-agent-1", ev.AgentId)
	assert.Equal(t, "event-message", ev.Message)
	assert.Equal(t, ts, ev.Timestamp)
	assert.Nil(t, ev.Error)

	inputEvent, err := ar.Events[1].AsInputEvent()
	require.NoError(t, err)
	assert.Equal(t, ts, inputEvent.Timestamp)
	assert.Equal(t, "test-action-2", inputEvent.ActionId)
	assert.Equal(t, "test-agent-2", inputEvent.AgentId)
	assert.Equal(t, "event-message", inputEvent.Message)
	assert.Equal(t, "input-type-2", inputEvent.ActionInputType)
	assert.NotNil(t, inputEvent.ActionData)
	assert.NotNil(t, inputEvent.ActionResponse)
	assert.Equal(t, ts, inputEvent.CompletedAt)
	assert.Equal(t, ts.Add(-1*time.Hour), inputEvent.StartedAt)
	assert.NotNil(t, inputEvent.Error)

	// Sanity check embedded *json.RawMessage here
	var obj map[string]interface{}
	err = json.Unmarshal(inputEvent.ActionData, &obj)
	require.NoError(t, err)
	v, ok := obj["key1"]
	require.True(t, ok)
	assert.Equal(t, "value1", v)

	p, err := json.Marshal(&ar)
	require.NoError(t, err)
	require.NotEmpty(t, p)

	upgEvent, err := ar.Events[2].AsUpgradeEvent()
	require.NoError(t, err)
	assert.Equal(t, ts, upgEvent.Timestamp)
	assert.Equal(t, "test-action-3", upgEvent.ActionId)
	assert.Equal(t, "test-agent-3", upgEvent.AgentId)
	assert.Equal(t, "event-message", upgEvent.Message)
	assert.True(t, upgEvent.Payload.Retry, "expected retry to be true")
	assert.Equal(t, 2, upgEvent.Payload.RetryAttempt)
	assert.NotNil(t, upgEvent.Error)
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

func Test_UpgradeDetailsMetadata_Downloading(t *testing.T) {
	tests := []struct {
		name string
		md   *UpgradeDetails_Metadata
		err  error
		pct  float64
		rate float64
	}{{
		name: "empty object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{}`),
		},
		err: nil,
		pct: 0,
	}, {
		name: "valid object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"download_percent":1,"download_rate":1000}`),
		},
		err:  nil,
		pct:  1,
		rate: 1000,
	}, {
		name: "invalid object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"download_percent":"potato"}`),
		},
		err: &json.UnsupportedValueError{},
	}, {
		name: "extra attributes",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"download_percent":1,"error_msg":"string","key":"value"}`),
		},
		err: nil,
		pct: 1,
	}, {
		name: "invalid extra object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"download_percent":1,"error_msg":1}`),
		},
		err: nil,
		pct: 1,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meta, err := tc.md.AsUpgradeMetadataDownloading()
			if tc.err == nil {
				assert.Equal(t, tc.pct, meta.DownloadPercent)
				if meta.DownloadRate != nil {
					assert.Equal(t, tc.rate, *meta.DownloadRate)
				}
			} else {
				assert.ErrorAsf(t, err, &tc.err, "error is %v", err)
			}
		})
	}
}

func Test_UpgradeDetailsMetadata_Failed(t *testing.T) {
	tests := []struct {
		name string
		md   *UpgradeDetails_Metadata
		err  error
		msg  string
	}{{
		name: "empty object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{}`),
		},
		err: nil,
		msg: "",
	}, {
		name: "valid object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"error_msg":"fail"}`),
		},
		err: nil,
		msg: "fail",
	}, {
		name: "invalid object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"error_msg":1}`),
		},
		err: &json.UnsupportedValueError{},
	}, {
		name: "extra attributes",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"download_percent":1,"error_msg":"fail","key":"value"}`),
		},
		err: nil,
		msg: "fail",
	}, {
		name: "invalid extra object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"download_percent":"potato","error_msg":"fail"}`),
		},
		err: nil,
		msg: "fail",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meta, err := tc.md.AsUpgradeMetadataFailed()
			if tc.err == nil {
				assert.Equal(t, tc.msg, meta.ErrorMsg)
			} else {
				assert.ErrorAsf(t, err, &tc.err, "error is %v", err)
			}
		})
	}
}

func Test_UpgradeDetailsMetadata_Scheduled(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name string
		md   *UpgradeDetails_Metadata
		err  error
		ts   time.Time
	}{{
		name: "empty object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{}`),
		},
		err: nil,
		ts:  time.Time{},
	}, {
		name: "valid object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"scheduled_at":"` + ts.Format(time.RFC3339) + `"}`),
		},
		err: nil,
		ts:  ts,
	}, {
		name: "invalid object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"scheduled_at":"potato"}`),
		},
		err: &json.UnsupportedValueError{},
	}, {
		name: "extra attributes",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"scheduled_at":"` + ts.Format(time.RFC3339) + `","key":"value","download_percent":1}`),
		},
		err: nil,
		ts:  ts,
	}, {
		name: "invalid extra object",
		md: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"scheduled_at":"` + ts.Format(time.RFC3339) + `","download_percent":"potato"}`),
		},
		err: nil,
		ts:  ts,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meta, err := tc.md.AsUpgradeMetadataScheduled()
			if tc.err == nil {
				assert.Equal(t, tc.ts, meta.ScheduledAt)
			} else {
				assert.ErrorAsf(t, err, &tc.err, "error is %v", err)
			}
		})
	}
}

func TestUpgradeDetailsSerialization(t *testing.T) {
	details := []UpgradeDetails{{
		ActionId: "test-action",
		Metadata: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"key":"value"}`),
		},
		State:         UpgradeDetailsStateUPGREQUESTED,
		TargetVersion: "1.2.3",
	}, {
		ActionId: "test-action",
		Metadata: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"download_percent":1}`),
		},
		State:         UpgradeDetailsStateUPGDOWNLOADING,
		TargetVersion: "1.2.3",
	}, {
		ActionId: "test-action",
		Metadata: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"error_msg":"fail","failed_state":"UPG_WATCHING"}`),
		},
		State:         UpgradeDetailsStateUPGFAILED,
		TargetVersion: "1.2.3",
	}, {
		ActionId: "test-action",
		Metadata: &UpgradeDetails_Metadata{
			union: json.RawMessage(`{"scheduled_at":"2022-01-02T12:00:00Z"}`),
		},
		State:         UpgradeDetailsStateUPGSCHEDULED,
		TargetVersion: "1.2.3",
	}}
	for _, d := range details {
		t.Run(string(d.State), func(t *testing.T) {
			p, err := json.Marshal(d)
			require.NoError(t, err)
			dd := UpgradeDetails{}
			err = json.Unmarshal(p, &dd)
			require.NoError(t, err)

			assert.Equal(t, d.ActionId, dd.ActionId)
			assert.Equal(t, d.State, dd.State)
			assert.Equal(t, d.TargetVersion, dd.TargetVersion)
			assert.Equal(t, string(d.Metadata.union), string(dd.Metadata.union))
		})
	}

}
