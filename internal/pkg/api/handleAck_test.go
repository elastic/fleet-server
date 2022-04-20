// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func BenchmarkMakeUpdatePolicyBody(b *testing.B) {
	b.ReportAllocs()

	const policyID = "ed110be4-c2a0-42b8-adc0-94c2f0569207"
	const newRev = 2
	const coord = 1

	for n := 0; n < b.N; n++ {
		makeUpdatePolicyBody(policyID, newRev, coord)
	}
}

func TestMakeUpdatePolicyBody(t *testing.T) {

	const policyID = "ed110be4-c2a0-42b8-adc0-94c2f0569207"
	const newRev = 2
	const coord = 1

	data := makeUpdatePolicyBody(policyID, newRev, coord)

	var i interface{}
	err := json.Unmarshal(data, &i)

	if err != nil {
		t.Fatal(err)
	}
}

func TestEventToActionResult(t *testing.T) {
	agentID := "6e9b6655-8cfe-4eb6-9b2f-c10aefae7517"

	tests := []struct {
		name string
		ev   Event
	}{
		{
			name: "success",
			ev: Event{
				ActionID:        "1b12dcd8-bde0-4045-92dc-c4b27668d733",
				ActionInputType: "osquery",
				StartedAt:       "2022-02-23T18:26:08.506128Z",
				CompletedAt:     "2022-02-23T18:26:08.507593Z",
				ActionData:      []byte(`{"query": "select * from osquery_info"}`),
				ActionResponse:  []byte(`{"osquery": {"count": 1}}`),
			},
		},
		{
			name: "error",
			ev: Event{
				ActionID:        "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				ActionInputType: "osquery",
				StartedAt:       "2022-02-24T18:26:08.506128Z",
				CompletedAt:     "2022-02-24T18:26:08.507593Z",
				ActionData:      []byte(`{"query": "select * from osquery_info"}`),
				Error:           "action undefined",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acr := eventToActionResult(agentID, tc.ev)
			assert.Equal(t, agentID, acr.AgentID)
			assert.Equal(t, tc.ev.ActionID, acr.ActionID)
			assert.Equal(t, tc.ev.ActionInputType, acr.ActionInputType)
			assert.Equal(t, tc.ev.StartedAt, acr.StartedAt)
			assert.Equal(t, tc.ev.CompletedAt, acr.CompletedAt)
			assert.Equal(t, tc.ev.ActionData, acr.ActionData)
			assert.Equal(t, tc.ev.ActionResponse, acr.ActionResponse)
			assert.Equal(t, tc.ev.Error, acr.Error)
		})
	}
}

// Mock bulker
type mockBulk struct {
	ftesting.MockBulk
	searchErr error
	createErr error
	updateErr error
	actions   []model.Action
}

type searchRequestFilter struct {
	Term struct {
		ActionID string `json:"action_id"`
	} `json:"term"`
}

type searchRequest struct {
	Query struct {
		Bool struct {
			Filter []searchRequestFilter `json:"filter"`
		} `json:"bool"`
	} `json:"query"`
}

func (m mockBulk) Search(ctx context.Context, index string, body []byte, opts ...bulk.Opt) (*es.ResultT, error) {
	if m.searchErr != nil {
		return nil, m.searchErr
	}

	if m.actions != nil {
		var req searchRequest
		err := json.Unmarshal(body, &req)
		if err != nil {
			return nil, err
		}

		var (
			action model.Action
			ok     bool
		)
		for _, a := range m.actions {
			if a.ActionID == req.Query.Bool.Filter[0].Term.ActionID {
				action = a
				ok = true
			}
		}
		if ok {
			return &es.ResultT{
				HitsT: es.HitsT{
					Hits: []es.HitT{
						{
							Source: []byte(`{"action_id":"` + action.ActionID + `","type":"` + action.Type + `"}`),
						},
					},
				},
			}, nil
		}
	}

	return &es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{},
		},
	}, nil
}

func (m mockBulk) Create(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) (string, error) {
	if m.createErr != nil {
		return "", m.createErr
	}
	i, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return i.String(), nil
}

func (m mockBulk) Update(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) error {
	return m.updateErr
}

func TestHandleAckEvents(t *testing.T) {
	// minimal sufficient config for the test
	cfg := &config.Server{
		Limits: config.ServerLimits{},
	}

	// Default mock bulker
	bulker := &mockBulk{}

	agent := &model.Agent{
		ESDocument: model.ESDocument{Id: "ab12dcd8-bde0-4045-92dc-c4b27668d735"},
		Agent:      &model.AgentMetadata{Version: "8.0.0"},
	}

	ctx := context.Background()

	newAckResponse := func(errors bool, items []AckResponseItem) AckResponse {
		return AckResponse{
			Action: "acks",
			Errors: errors,
			Items:  items,
		}
	}
	newAckResponseItem := func(status int) AckResponseItem {
		return AckResponseItem{
			Status:  status,
			Message: http.StatusText(status),
		}
	}

	tests := []struct {
		name   string
		events []Event
		res    AckResponse
		err    error
		bulker bulk.Bulk
	}{
		{
			name: "nil",
			res:  newAckResponse(false, []AckResponseItem{}),
		},
		{
			name:   "empty",
			events: []Event{},
			res:    newAckResponse(false, []AckResponseItem{}),
		},
		{
			name: "action agentID mismatch",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
					AgentID:  "ab12dcd8-bde0-4045-92dc-c4b27668d737",
				},
			},
			res: newAckResponse(true, []AckResponseItem{newAckResponseItem(http.StatusBadRequest)}),
			err: &HTTPError{Status: http.StatusBadRequest},
		},
		{
			name: "action empty agent id",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
			},
			res: newAckResponse(true, []AckResponseItem{newAckResponseItem(http.StatusNotFound)}),
			err: &HTTPError{Status: http.StatusNotFound},
		},
		{
			name: "action find error",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
			},
			res:    newAckResponse(true, []AckResponseItem{newAckResponseItem(http.StatusInternalServerError)}),
			bulker: mockBulk{searchErr: errors.New("network error")},
			err:    &HTTPError{Status: http.StatusInternalServerError},
		},
		{
			name: "policy action",
			events: []Event{
				{
					ActionID: "policy:2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
			},
			res: newAckResponse(false, []AckResponseItem{{
				Status:  http.StatusOK,
				Message: http.StatusText(http.StatusOK),
			}}),
		},
		{
			name: "action found",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
			},
			res: newAckResponse(false, []AckResponseItem{{
				Status:  http.StatusOK,
				Message: http.StatusText(http.StatusOK),
			}}),
			bulker: mockBulk{actions: []model.Action{
				{ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733"},
			}},
		},
		{
			name: "action found, create result general error",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
			},
			res: newAckResponse(true, []AckResponseItem{newAckResponseItem(http.StatusInternalServerError)}),
			bulker: mockBulk{
				actions: []model.Action{
					{ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733"},
				},
				createErr: errors.New("network error"),
			},
			err: &HTTPError{Status: http.StatusInternalServerError},
		},
		{
			name: "action found, create result elasticsearch error",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
			},
			res: newAckResponse(true, []AckResponseItem{newAckResponseItem(http.StatusServiceUnavailable)}),
			bulker: mockBulk{
				actions: []model.Action{
					{ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733"},
				},
				createErr: &es.ErrElastic{Status: http.StatusServiceUnavailable, Reason: http.StatusText(http.StatusServiceUnavailable)},
			},
			err: &HTTPError{Status: http.StatusServiceUnavailable},
		},
		{
			name: "upgrade action found, update agent error",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
					Type:     "UPGRADE",
				},
			},
			res: newAckResponse(true, []AckResponseItem{{
				Status:  http.StatusServiceUnavailable,
				Message: http.StatusText(http.StatusServiceUnavailable),
			}}),
			bulker: mockBulk{
				actions: []model.Action{
					{ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733", Type: "UPGRADE"},
				},
				updateErr: &es.ErrElastic{Status: http.StatusServiceUnavailable, Reason: http.StatusText(http.StatusServiceUnavailable)},
			},
			err: &HTTPError{Status: http.StatusServiceUnavailable},
		},
		{
			name: "mixed actions found",
			events: []Event{
				{
					ActionID: "policy:2b12dcd8-bde0-4045-92dc-c4b27668d733:1:1",
					Type:     "POLICY_CHANGE",
				},
				{
					ActionID: "1b12dcd8-bde0-4045-92dc-c4b27668d731",
					Type:     "UNENROLL",
				},
				{
					ActionID: "1b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
				{
					ActionID: "ab12dcd8-bde0-4045-92dc-c4b27668d73a",
					Type:     "UPGRADE",
				},
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
				{
					ActionID: "policy:2b12dcd8-bde0-4045-92dc-c4b27668d733:1:2",
					Type:     "POLICY_CHANGE",
				},
			},
			res: newAckResponse(true, []AckResponseItem{
				{
					Status:  http.StatusOK,
					Message: http.StatusText(http.StatusOK),
				},
				{
					Status:  http.StatusOK,
					Message: http.StatusText(http.StatusOK),
				},
				{
					Status:  http.StatusNotFound,
					Message: http.StatusText(http.StatusNotFound),
				},
				{
					Status:  http.StatusOK,
					Message: http.StatusText(http.StatusOK),
				},
				{
					Status:  http.StatusOK,
					Message: http.StatusText(http.StatusOK),
				},
				{
					Status:  http.StatusOK,
					Message: http.StatusText(http.StatusOK),
				},
			}),
			bulker: mockBulk{actions: []model.Action{
				{ActionID: "policy:2b12dcd8-bde0-4045-92dc-c4b27668d733:1:1"},
				{ActionID: "1b12dcd8-bde0-4045-92dc-c4b27668d731", Type: "UNENROLL"},
				{ActionID: "ab12dcd8-bde0-4045-92dc-c4b27668d73a", Type: "UPGRADE"},
				{ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733"},
			}},
			err: &HTTPError{Status: http.StatusNotFound},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache, err := cache.New(cache.Config{NumCounters: 100, MaxCost: 100000})
			if err != nil {
				t.Fatal(err)
			}

			b := tc.bulker
			if b == nil {
				b = bulker
			}
			ack := NewAckT(cfg, b, cache)

			res, err := ack.handleAckEvents(ctx, log.Logger, agent, tc.events)
			assert.Equal(t, tc.res, res)

			if err != nil {
				if tc.err != nil {
					diff := cmp.Diff(err, tc.err)
					if diff != "" {
						t.Fatal(diff)
					}
				} else {
					t.Fatalf("expected err: nil, got: %v", err)
				}
			} else {
				if tc.err != nil {
					t.Fatalf("expected err: %v, got: nil", tc.err)
				}
			}
		})
	}
}
