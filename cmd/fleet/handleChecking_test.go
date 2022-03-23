// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package fleet

import (
	"encoding/json"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestConvertActionsEmpty(t *testing.T) {
	resp, token := convertActions("1234", nil)
	assert.Equal(t, resp, []ActionResp{})
	assert.Equal(t, token, "")
}

func TestConvertActions(t *testing.T) {
	actions := []model.Action{
		{
			ActionID: "1234",
		},
	}
	resp, token := convertActions("agent-id", actions)
	assert.Equal(t, resp, []ActionResp{
		{
			AgentId: "agent-id",
			Id:      "1234",
			Data:    json.RawMessage(nil),
		},
	})
	assert.Equal(t, token, "")
}
