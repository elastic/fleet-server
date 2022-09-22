// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

const (
	AgentActionSavedObjectType = "fleet-agent-actions"
)

const (
	TypePolicyChange = "POLICY_CHANGE"
	TypeUnenroll     = "UNENROLL"
	TypeUpgrade      = "UPGRADE"
)

const kFleetAccessRolesJSON = `
{
	"fleet-apikey-access": {
		"cluster": [],
		"applications": [{
			"application": "fleet",
			"privileges": ["no-privileges"],
			"resources": ["*"]
		}]
	}
}
`

// AgentAction details agent action payload
// Wrong: no AAD;
// This defeats the signature check;
// can copy from one to another and will dispatch.
type AgentAction struct {
	AgentID   string `json:"agent_id"`
	Type      string `json:"type"`
	SentAt    string `json:"sent_at"`
	CreatedAt string `json:"created_at"`
	Data      string `json:"data" saved:"encrypt"`
}

type EnrollRequest struct {
	Type     string `json:"type"`
	SharedID string `json:"shared_id"`
	Meta     struct {
		User  json.RawMessage `json:"user_provided"`
		Local json.RawMessage `json:"local"`
		Tags  []string        `json:"tags"`
	} `json:"metadata"`
}

type EnrollResponseItem struct {
	ID             string          `json:"id"`
	Active         bool            `json:"active"`
	PolicyID       string          `json:"policy_id"`
	Type           string          `json:"type"`
	EnrolledAt     string          `json:"enrolled_at"`
	UserMeta       json.RawMessage `json:"user_provided_metadata"`
	LocalMeta      json.RawMessage `json:"local_metadata"`
	Actions        []interface{}   `json:"actions"`
	AccessAPIKeyID string          `json:"access_api_key_id"`
	AccessAPIKey   string          `json:"access_api_key"`
	Status         string          `json:"status"`
	Tags           []string        `json:"tags"`
}

type EnrollResponse struct {
	Action string             `json:"action"`
	Item   EnrollResponseItem `json:"item"`
}

type CheckinRequest struct {
	Status    string          `json:"status"`
	Message   string          `json:"message"`
	AckToken  string          `json:"ack_token,omitempty"`
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

type AckResponseItem struct {
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
}

type AckResponse struct {
	Action string            `json:"action"`
	Errors bool              `json:"errors,omitempty"` // indicates that some of the events in the ack request failed
	Items  []AckResponseItem `json:"items,omitempty"`
}

func NewAckResponse(size int) AckResponse {
	return AckResponse{
		Action: "acks",
		Items:  make([]AckResponseItem, size),
	}
}

func (a *AckResponse) setMessage(pos int, status int, message string) {
	if status != http.StatusOK {
		a.Errors = true
	}
	a.Items[pos].Status = status
	a.Items[pos].Message = message
}

func (a *AckResponse) SetResult(pos int, status int) {
	a.setMessage(pos, status, http.StatusText(status))
}

func (a *AckResponse) SetError(pos int, err error) {
	var esErr *es.ErrElastic
	if errors.As(err, &esErr) {
		a.setMessage(pos, esErr.Status, esErr.Reason)
	} else {
		a.SetResult(pos, http.StatusInternalServerError)
	}
}

type ActionResp struct {
	AgentID    string      `json:"agent_id"`
	CreatedAt  string      `json:"created_at"`
	StartTime  string      `json:"start_time,omitempty"`
	Expiration string      `json:"expiration,omitempty"`
	Data       interface{} `json:"data"`
	ID         string      `json:"id"`
	Type       string      `json:"type"`
	InputType  string      `json:"input_type"`
	Timeout    int64       `json:"timeout,omitempty"`
}

type Event struct {
	Type            string          `json:"type"`
	SubType         string          `json:"subtype"`
	AgentID         string          `json:"agent_id"`
	ActionID        string          `json:"action_id"`
	ActionInputType string          `json:"action_input_type"`
	PolicyID        string          `json:"policy_id"`
	StreamID        string          `json:"stream_id"`
	Timestamp       string          `json:"timestamp"`
	Message         string          `json:"message"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	StartedAt       string          `json:"started_at"`
	CompletedAt     string          `json:"completed_at"`
	ActionData      json.RawMessage `json:"action_data,omitempty"`
	ActionResponse  json.RawMessage `json:"action_response,omitempty"`
	Data            json.RawMessage `json:"data,omitempty"`
	Error           string          `json:"error,omitempty"`
}

type StatusResponseVersion struct {
	Number    string `json:"number,omitempty"`
	BuildHash string `json:"build_hash,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
}

type StatusResponse struct {
	Name    string                 `json:"name"`
	Status  string                 `json:"status"`
	Version *StatusResponseVersion `json:"version,omitempty"`
}

type FileInfo struct {
	Size      int64  `json:"size"`
	Name      string `json:"name"`
	Extension string `json:"ext"`
	Mime      string `json:"mime_type"`
}
