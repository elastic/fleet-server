// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

//nolint:dupl // test cases have some duplication
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

// matchAction will decode a response body and attempt to match the query ID with the provided value
// It is meant to be wrapped by mock.MatchedBy for example:
// m.On("Search", mock.Anything, "some-index", mock.MatchedBy(matchAction(t, "actionID)), mock.Anything)
func matchAction(tb testing.TB, actionID string) func(body []byte) bool {
	return func(body []byte) bool {
		tb.Helper()
		var req searchRequest
		if err := json.Unmarshal(body, &req); err != nil {
			tb.Fatal(err)
		}
		return actionID == req.Query.Bool.Filter[0].Term.ActionID
	}
}

func TestHandleAckEvents(t *testing.T) {
	// minimal sufficient config for the test
	cfg := &config.Server{
		Limits: config.ServerLimits{},
	}

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
		bulker func(t *testing.T) *ftesting.MockBulk
	}{
		{
			name: "nil",
			res:  newAckResponse(false, []AckResponseItem{}),
			bulker: func(t *testing.T) *ftesting.MockBulk {
				return ftesting.NewMockBulk()
			},
		},
		{
			name:   "empty",
			events: []Event{},
			res:    newAckResponse(false, []AckResponseItem{}),
			bulker: func(t *testing.T) *ftesting.MockBulk {
				return ftesting.NewMockBulk()
			},
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
			bulker: func(t *testing.T) *ftesting.MockBulk {
				return ftesting.NewMockBulk()
			},
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
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{}, nil)
				return m
			},
		},
		{
			name: "action find error",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
			},
			res: newAckResponse(true, []AckResponseItem{newAckResponseItem(http.StatusInternalServerError)}),
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{}, errors.New("network error"))
				return m
			},
			err: &HTTPError{Status: http.StatusInternalServerError},
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
			bulker: func(t *testing.T) *ftesting.MockBulk {
				return ftesting.NewMockBulk()
			},
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
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "2b12dcd8-bde0-4045-92dc-c4b27668d733")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"2b12dcd8-bde0-4045-92dc-c4b27668d733","type":"UPGRADE"}`),
					}},
				}}, nil)
				m.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				return m
			},
		},
		{
			name: "action found, create result general error",
			events: []Event{
				{
					ActionID: "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				},
			},
			res: newAckResponse(true, []AckResponseItem{newAckResponseItem(http.StatusInternalServerError)}),
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "2b12dcd8-bde0-4045-92dc-c4b27668d733")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"2b12dcd8-bde0-4045-92dc-c4b27668d733","type":"UPGRADE"}`),
					}},
				}}, nil)
				m.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", errors.New("network error"))
				return m
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
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "2b12dcd8-bde0-4045-92dc-c4b27668d733")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"2b12dcd8-bde0-4045-92dc-c4b27668d733","type":"UPGRADE"}`),
					}},
				}}, nil)
				m.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", &es.ErrElastic{Status: http.StatusServiceUnavailable, Reason: http.StatusText(http.StatusServiceUnavailable)})
				return m
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
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "2b12dcd8-bde0-4045-92dc-c4b27668d733")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"2b12dcd8-bde0-4045-92dc-c4b27668d733","type":"UPGRADE"}`),
					}},
				}}, nil)
				m.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", &es.ErrElastic{Status: http.StatusServiceUnavailable, Reason: http.StatusText(http.StatusServiceUnavailable)})
				return m
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
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "2b12dcd8-bde0-4045-92dc-c4b27668d733")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"2b12dcd8-bde0-4045-92dc-c4b27668d733","type":"POLICY_CHANGE"}`),
					}},
				}}, nil)
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "1b12dcd8-bde0-4045-92dc-c4b27668d731")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"1b12dcd8-bde0-4045-92dc-c4b27668d731","type":"UNENROLL"}`),
					}},
				}}, nil)
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "1b12dcd8-bde0-4045-92dc-c4b27668d733")), mock.Anything).Return(&es.ResultT{}, nil)
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "ab12dcd8-bde0-4045-92dc-c4b27668d73a")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"ab12dcd8-bde0-4045-92dc-c4b27668d73a","type":"UPGRADE"}`),
					}},
				}}, nil)
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "2b12dcd8-bde0-4045-92dc-c4b27668d733")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"2b12dcd8-bde0-4045-92dc-c4b27668d733"}`),
					}},
				}}, nil)
				m.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
				m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				return m
			},
			err: &HTTPError{Status: http.StatusNotFound},
		},
		{
			name: "upgrade action failed",
			events: []Event{
				{
					ActionID: "ab12dcd8-bde0-4045-92dc-c4b27668d73a",
					Type:     "UPGRADE",
					Error:    "Error with no payload",
				},
			},
			res: newAckResponse(false, []AckResponseItem{
				{
					Status:  http.StatusOK,
					Message: http.StatusText(http.StatusOK),
				},
			}),
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "ab12dcd8-bde0-4045-92dc-c4b27668d73a")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"ab12dcd8-bde0-4045-92dc-c4b27668d73a","type":"UPGRADE"}`),
					}},
				}}, nil).Once()
				m.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil).Once()
				m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				return m
			},
		},
		{
			name: "upgrade action retrying",
			events: []Event{
				{
					ActionID: "ab12dcd8-bde0-4045-92dc-c4b27668d73a",
					Type:     "UPGRADE",
					Error:    "Error with payload",
					Payload:  json.RawMessage(`{"retry":true,"retry_attempt":1}`),
				},
			},
			res: newAckResponse(false, []AckResponseItem{
				{
					Status:  http.StatusOK,
					Message: http.StatusText(http.StatusOK),
				},
			}),
			bulker: func(t *testing.T) *ftesting.MockBulk {
				m := ftesting.NewMockBulk()
				m.On("Search", mock.Anything, mock.Anything, mock.MatchedBy(matchAction(t, "ab12dcd8-bde0-4045-92dc-c4b27668d73a")), mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
					Hits: []es.HitT{{
						Source: []byte(`{"action_id":"ab12dcd8-bde0-4045-92dc-c4b27668d73a","type":"UPGRADE"}`),
					}},
				}}, nil).Once()
				m.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil).Once()
				m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				return m
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			cache, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
			if err != nil {
				t.Fatal(err)
			}

			bulker := tc.bulker(t)
			ack := NewAckT(cfg, bulker, cache)

			res, err := ack.handleAckEvents(ctx, logger, agent, tc.events)
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
			bulker.AssertExpectations(t)
		})
	}
}

func TestInvalidateAPIKeys(t *testing.T) {
	toRetire1 := []model.ToRetireAPIKeyIdsItems{{
		ID: "toRetire1",
	}}
	toRetire2 := []model.ToRetireAPIKeyIdsItems{{
		ID: "toRetire2_0",
	}, {
		ID: "toRetire2_1",
	}}
	var toRetire3 []model.ToRetireAPIKeyIdsItems

	skips := map[string]string{
		"1": "toRetire1",
		"2": "toRetire2_0",
		"3": "",
	}
	wants := map[string][]string{
		"1": {},
		"2": {"toRetire2_1"},
		"3": {},
	}

	agent := model.Agent{
		Outputs: map[string]*model.PolicyOutput{
			"1": {ToRetireAPIKeyIds: toRetire1},
			"2": {ToRetireAPIKeyIds: toRetire2},
			"3": {ToRetireAPIKeyIds: toRetire3},
		},
	}

	for i, out := range agent.Outputs {
		skip := skips[i]
		want := wants[i]

		bulker := ftesting.NewMockBulk()
		if len(want) > 0 {
			bulker.On("APIKeyInvalidate",
				context.Background(), mock.MatchedBy(func(ids []string) bool {
					// if A contains B and B contains A => A = B
					return assert.Subset(t, ids, want) &&
						assert.Subset(t, want, ids)
				})).
				Return(nil)
		}

		ack := &AckT{bulk: bulker}
		ack.invalidateAPIKeys(context.Background(), out.ToRetireAPIKeyIds, skip)

		bulker.AssertExpectations(t)
	}
}

func TestAckHandleUpgrade(t *testing.T) {
	tests := []struct {
		name   string
		event  Event
		bulker func(t *testing.T) *ftesting.MockBulk
	}{{
		name:  "ok",
		event: Event{},
		bulker: func(t *testing.T) *ftesting.MockBulk {
			m := ftesting.NewMockBulk()
			m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			return m
		},
	}, {
		name: "retry signaled",
		event: Event{
			Error:   "upgrade error",
			Payload: json.RawMessage(`{"retry":true,"retry_attempt":1}`),
		},
		bulker: func(t *testing.T) *ftesting.MockBulk {
			m := ftesting.NewMockBulk()
			m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(func(p []byte) bool {
				var body struct {
					Doc struct {
						Status string `json:"upgrade_status"`
					} `json:"doc"`
				}
				if err := json.Unmarshal(p, &body); err != nil {
					t.Fatal(err)
				}
				return body.Doc.Status == "retrying"
			}), mock.Anything).Return(nil).Once()
			return m
		},
	}, {
		name: "no more retries",
		event: Event{
			Error:   "upgrade error",
			Payload: json.RawMessage(`{"retry":false}`),
		},
		bulker: func(t *testing.T) *ftesting.MockBulk {
			m := ftesting.NewMockBulk()
			m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(func(p []byte) bool {
				var body struct {
					Doc struct {
						Status string `json:"upgrade_status"`
					} `json:"doc"`
				}
				if err := json.Unmarshal(p, &body); err != nil {
					t.Fatal(err)
				}
				return body.Doc.Status == ""
			}), mock.Anything).Return(nil).Once()
			return m
		},
	}}
	cfg := &config.Server{
		Limits: config.ServerLimits{},
	}
	agent := &model.Agent{
		ESDocument: model.ESDocument{Id: "ab12dcd8-bde0-4045-92dc-c4b27668d735"},
		Agent:      &model.AgentMetadata{Version: "8.0.0"},
	}
	ctx := context.Background()
	cache, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			bulker := tc.bulker(t)
			ack := NewAckT(cfg, bulker, cache)

			err := ack.handleUpgrade(ctx, logger, agent, tc.event)
			assert.NoError(t, err)
			bulker.AssertExpectations(t)
		})
	}
}
