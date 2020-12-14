// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"encoding/json"
)

const (
	AGENT_SAVED_OBJECT_TYPE               = "fleet-agents"
	ENROLLMENT_API_KEYS_SAVED_OBJECT_TYPE = "fleet-enrollment-api-keys"
	AGENT_ACTION_SAVED_OBJECT_TYPE        = "fleet-agent-actions"
)

const (
	TypePolicyChange = "POLICY_CHANGE"
)

const (
	FieldPolicyRev     = "policy_revision"
	FieldPackages      = "packages"
	FieldLastCheckin   = "last_checkin"
	FieldLocalMetadata = "local_metadata"
)

const kFleetAccessRolesJSON = `
{
	"fleet-apikey-access": {
		"cluster": [],
		"applications": [{
			"application": ".fleet",
			"privileges": ["no-privileges"],
			"resources": ["*"]
		}]
	}
}
`

const kFleetOutputRolesJSON = `
{
	"fleet-output": {
		"cluster": ["monitor"],
		"index": [{
			"names": [
				"logs-*",
				"metrics-*",
				"events-*",
				".ds-logs-*",
				".ds-metrics-*",
				".ds-events-*"
			],
			"privileges": [
				"write",
				"create_index",
				"indices:admin/auto_create"
			]
		}]
	}
}
`

// Wrong: no AAD;
// This defeats the signature check;
// can copy from one to another and will dispatch.
type AgentAction struct {
	AgentId   string `json:"agent_id"`
	Type      string `json:"type"`
	SentAt    string `json:"sent_at"`
	CreatedAt string `json:"created_at"`
	Data      string `json:"data" saved:"encrypt"`
}

type EnrollRequest struct {
	Type     string `json:"type"`
	SharedId string `json:"shared_id"`
	Meta     struct {
		User  json.RawMessage `json:"user_provided"`
		Local json.RawMessage `json:"local"`
	} `json:"metadata"`
}

type EnrollResponseItem struct {
	ID             string          `json:"id"`
	Active         bool            `json:"active"`
	PolicyId       string          `json:"policy_id"`
	Type           string          `json:"type"`
	EnrolledAt     string          `json:"enrolled_at"`
	UserMeta       json.RawMessage `json:"user_provided_metadata"`
	LocalMeta      json.RawMessage `json:"local_metadata"`
	Actions        []interface{}   `json:"actions"`
	AccessApiKeyId string          `json:"access_api_key_id"`
	AccessAPIKey   string          `json:"access_api_key"`
	Status         string          `json:"status"`
}

type EnrollResponse struct {
	Action string             `json:"action"`
	Item   EnrollResponseItem `json:"item"`
}

type CheckinRequest struct {
	AckToken  string          `json:"ack_token,omitempty"`
	Events    []Event         `json:"events"`
	LocalMeta json.RawMessage `json:"local_metadata"`
}

type CheckinResponse struct {
	AckToken string       `json:"ack_token,omitempty"`
	Action   string       `json:"action"`
	Actions  []ActionResp `json:"actions,omitempty"`
}

type AckRequest struct {
	Events []Event `json:"events"`
}

type AckResponse struct {
	Action string `json:"action"`
}

type ActionResp struct {
	AgentId   string          `json:"agent_id"`
	CreatedAt string          `json:"created_at"`
	Data      json.RawMessage `json:"data"`
	Id        string          `json:"id"`
	Type      string          `json:"type"`
}

type Event struct {
	Type      string `json:"type"`
	SubType   string `json:"subtype"`
	AgentId   string `json:"agent_id"`
	ActionId  string `json:"action_id"`
	PolicyId  string `json:"policy_id"`
	StreamId  string `json:"stream_id"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	Payload   string `json:"payload"`
	Data      string `json:"data"`
}

type Action struct {
	Id        string `json:"-"`
	AgentId   string `json:"agent_id,omitempty"`
	PolicyId  string `json:"policy_id,omitempty" saved:"aad"`
	PolicyRev int64  `json:"policy_revision,omitempty" saved:"aad"`
	Type      string `json:"type"`
	Data      string `json:"data" saved:"encrypt"`
	AckData   string `json:"ack_data" saved:"aad"`
	SentAt    string `json:"sent_at"`
	CreatedAt string `json:"created_at"`
}
