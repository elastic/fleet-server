// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package api

import (
	"encoding/json"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestConvertActions(t *testing.T) {
	tests := []struct {
		name    string
		actions []model.Action
		resp    []ActionResp
		token   string
	}{{
		name:    "empty actions",
		actions: nil,
		resp:    []ActionResp{},
		token:   "",
	}, {
		name:    "single action",
		actions: []model.Action{{ActionID: "1234"}},
		resp: []ActionResp{{
			AgentID: "agent-id",
			ID:      "1234",
			Data:    json.RawMessage(nil),
		}},
		token: "",
	}, {
		name: "multiple actions",
		actions: []model.Action{
			{ActionID: "1234"},
			{ActionID: "5678"},
		},
		resp: []ActionResp{{
			AgentID: "agent-id",
			ID:      "1234",
			Data:    json.RawMessage(nil),
		}, {
			AgentID: "agent-id",
			ID:      "5678",
			Data:    json.RawMessage(nil),
		}},
		token: "",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, token := convertActions("agent-id", tc.actions)
			assert.Equal(t, tc.resp, resp)
			assert.Equal(t, tc.token, token)
		})
	}
}

func TestFilterActions(t *testing.T) {
	tests := []struct {
		name    string
		actions []model.Action
		resp    []model.Action
	}{{
		name:    "empty list",
		actions: []model.Action{},
		resp:    []model.Action{},
	}, {
		name: "nothing filtered",
		actions: []model.Action{{
			ActionID: "1234",
		}, {
			ActionID: "5678",
		}},
		resp: []model.Action{{
			ActionID: "1234",
		}, {
			ActionID: "5678",
		}},
	}, {
		name: "filter POLICY_CHANGE action",
		actions: []model.Action{{
			ActionID: "1234",
			Type:     TypePolicyChange,
		}, {
			ActionID: "5678",
		}},
		resp: []model.Action{{
			ActionID: "5678",
		}},
	}, {
		name: "filter UPDATE_TAGS action",
		actions: []model.Action{{
			ActionID: "1234",
			Type:     TypeUpdateTags,
		}},
		resp: []model.Action{},
	}, {
		name: "filter FORCE_UNENROLL action",
		actions: []model.Action{{
			ActionID: "1234",
			Type:     TypeForceUnenroll,
		}},
		resp: []model.Action{},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := filterActions("agent-id", tc.actions)
			assert.Equal(t, tc.resp, resp)
		})
	}
}
