// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

//nolint:dupl // test cases have some duplication
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	const policyID = "ed110be4-c2a0-42b8-adc0-94c2f0569207"
	const newRev = 2

	b.ResetTimer()
	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		makeUpdatePolicyBody(policyID, newRev)
	}
}

func TestMakeUpdatePolicyBody(t *testing.T) {
	const policyID = "ed110be4-c2a0-42b8-adc0-94c2f0569207"
	const newRev = 2

	data := makeUpdatePolicyBody(policyID, newRev)

	var i interface{}
	err := json.Unmarshal(data, &i)

	if err != nil {
		t.Fatal(err)
	}
}

func TestEventToActionResult(t *testing.T) {
	agentID := "6e9b6655-8cfe-4eb6-9b2f-c10aefae7517"
	t.Run("generic", func(t *testing.T) {
		r := eventToActionResult(agentID, "UPGRADE", []string{}, AckRequest_Events_Item{json.RawMessage(`{
		"action_id": "test-action-id",
		"message": "action message",
		"timestamp": "2022-02-23T18:26:08.506128Z"
	    }`)})
		assert.Equal(t, agentID, r.AgentID)
		assert.Equal(t, "test-action-id", r.ActionID)
		assert.Equal(t, "2022-02-23T18:26:08.506128Z", r.Timestamp)
		assert.Empty(t, r.Error)
	})
	t.Run("with error", func(t *testing.T) {
		r := eventToActionResult(agentID, "UPGRADE", []string{}, AckRequest_Events_Item{json.RawMessage(`{
		"action_id": "test-action-id",
		"message": "action message",
		"timestamp": "2022-02-23T18:26:08.506128Z",
		"error": "error message"
	    }`)})
		assert.Equal(t, agentID, r.AgentID)
		assert.Equal(t, "test-action-id", r.ActionID)
		assert.Equal(t, "2022-02-23T18:26:08.506128Z", r.Timestamp)
		assert.Equal(t, "error message", r.Error)
	})
	t.Run("request diagnostics", func(t *testing.T) {
		r := eventToActionResult(agentID, "REQUEST_DIAGNOSTICS", []string{}, AckRequest_Events_Item{json.RawMessage(`{
		"action_id": "test-action-id",
		"message": "action message",
		"timestamp": "2022-02-23T18:26:08.506128Z",
		"data": {"upload_id": "upload"},
		"error": "error message"
	    }`)})
		assert.Equal(t, agentID, r.AgentID)
		assert.Equal(t, "test-action-id", r.ActionID)
		assert.Equal(t, "2022-02-23T18:26:08.506128Z", r.Timestamp)
		assert.Equal(t, json.RawMessage(`{"upload_id":"upload"}`), r.Data)
		assert.Equal(t, "error message", r.Error)
	})
	t.Run("input action", func(t *testing.T) {
		r := eventToActionResult(agentID, "INPUT_ACTION", []string{}, AckRequest_Events_Item{json.RawMessage(`{
		"action_id": "test-action-id",
		"message": "action message",
		"timestamp": "2022-02-23T18:26:08.506128Z",
		"action_input_type": "test-input",
		"action_data": {"key1":"value1"},
		"action_response": {"key2":"value2"},
		"completed_at": "2022-02-24T18:26:08.506128Z",
		"error": "error message",
		"started_at": "2022-02-22T18:26:08.506128Z"
	    }`)})
		assert.Equal(t, agentID, r.AgentID)
		assert.Equal(t, "test-action-id", r.ActionID)
		assert.Equal(t, "2022-02-23T18:26:08.506128Z", r.Timestamp)
		assert.Equal(t, "test-input", r.ActionInputType)
		assert.Equal(t, json.RawMessage(`{"key1":"value1"}`), r.ActionData)
		assert.Equal(t, json.RawMessage(`{"key2":"value2"}`), r.ActionResponse)
		assert.Equal(t, "2022-02-24T18:26:08.506128Z", r.CompletedAt)
		assert.Equal(t, "2022-02-22T18:26:08.506128Z", r.StartedAt)
		assert.Equal(t, "error message", r.Error)
	})
	t.Run("migrate action", func(t *testing.T) {
		r := eventToActionResult(agentID, "MIGRATE", []string{}, AckRequest_Events_Item{json.RawMessage(`{
		"action_id": "test-action-id",
		"message": "action message",
		"timestamp": "2022-02-23T18:26:08.506128Z",
		"data": {"enrollment_token":"et","policy_id":"pid","target_uri":"turi"},
		"error": "error message"
		}`)})
		assert.Equal(t, agentID, r.AgentID)
		assert.Equal(t, "test-action-id", r.ActionID)
		assert.Equal(t, "2022-02-23T18:26:08.506128Z", r.Timestamp)
		assert.Equal(t, "error message", r.Error)
	})
	t.Run("privilege level change action", func(t *testing.T) {
		r := eventToActionResult(agentID, "PRIVILEGE_LEVEL_CHANGE", []string{}, AckRequest_Events_Item{json.RawMessage(`{
		"action_id": "test-action-id",
		"message": "action message",
		"timestamp": "2022-02-23T18:26:08.506128Z",
		"data": {"unprivileged":"true","user_info":{"username": "demo", "password": "1q2w3e"}},
		"error": "error message"
		}`)})
		assert.Equal(t, agentID, r.AgentID)
		assert.Equal(t, "test-action-id", r.ActionID)
		assert.Equal(t, "2022-02-23T18:26:08.506128Z", r.Timestamp)
		assert.Equal(t, "error message", r.Error)
	})
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
		s := http.StatusText(status)
		return AckResponseItem{
			Status:  status,
			Message: &s,
		}
	}

	tests := []struct {
		name   string
		events []AckRequest_Events_Item
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
			events: []AckRequest_Events_Item{},
			res:    newAckResponse(false, []AckResponseItem{}),
			bulker: func(t *testing.T) *ftesting.MockBulk {
				return ftesting.NewMockBulk()
			},
		},
		{
			name: "action agentID mismatch",
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				"agent_id": "ab12dcd8-bde0-4045-92dc-c4b27668d737"
			    }`),
			}},
			res: newAckResponse(true, []AckResponseItem{newAckResponseItem(http.StatusBadRequest)}),
			err: &HTTPError{Status: http.StatusBadRequest},
			bulker: func(t *testing.T) *ftesting.MockBulk {
				return ftesting.NewMockBulk()
			},
		},
		{
			name: "action empty agent id",
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "2b12dcd8-bde0-4045-92dc-c4b27668d733"
			    }`),
			}},
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
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "2b12dcd8-bde0-4045-92dc-c4b27668d733"
			    }`),
			}},
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
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				    "action_id": "policy:2b12dcd8-bde0-4045-92dc-c4b27668d733"
			    }`),
			}},
			res: newAckResponse(false, []AckResponseItem{{
				Status:  http.StatusOK,
				Message: ptr(http.StatusText(http.StatusOK)),
			}}),
			bulker: func(t *testing.T) *ftesting.MockBulk {
				return ftesting.NewMockBulk()
			},
		},
		{
			name: "action found",
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "2b12dcd8-bde0-4045-92dc-c4b27668d733"
			    }`),
			}},
			res: newAckResponse(false, []AckResponseItem{{
				Status:  http.StatusOK,
				Message: ptr(http.StatusText(http.StatusOK)),
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
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "2b12dcd8-bde0-4045-92dc-c4b27668d733"
			    }`),
			}},
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
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "2b12dcd8-bde0-4045-92dc-c4b27668d733"
			    }`),
			}},
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
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "2b12dcd8-bde0-4045-92dc-c4b27668d733"
			    }`), // an UPGRADE action
			}},
			res: newAckResponse(true, []AckResponseItem{{
				Status:  http.StatusServiceUnavailable,
				Message: ptr(http.StatusText(http.StatusServiceUnavailable)),
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
			events: []AckRequest_Events_Item{
				{
					json.RawMessage(`{
				    "action_id": "policy:2b12dcd8-bde0-4045-92dc-c4b27668d733:1:1"
				}`), // POLICY_CHANGE action
				},
				{
					json.RawMessage(`{
				    "action_id": "1b12dcd8-bde0-4045-92dc-c4b27668d731"
				}`), // UNENROLL action
				},
				{
					json.RawMessage(`{
				    "action_id": "1b12dcd8-bde0-4045-92dc-c4b27668d733"
				}`), // no matching action
				},
				{
					json.RawMessage(`{
				    "action_id": "ab12dcd8-bde0-4045-92dc-c4b27668d73a"
				}`), // UPGRADE action
				},
				{
					json.RawMessage(`{
				    "action_id": "2b12dcd8-bde0-4045-92dc-c4b27668d733"
				}`), // untyped action
				},
				{
					json.RawMessage(`{
				    "action_id": "policy:2b12dcd8-bde0-4045-92dc-c4b27668d733:1:2"
				}`), // POLICY_CHANGE
				},
			},
			res: newAckResponse(true, []AckResponseItem{
				{
					Status:  http.StatusOK,
					Message: ptr(http.StatusText(http.StatusOK)),
				},
				{
					Status:  http.StatusOK,
					Message: ptr(http.StatusText(http.StatusOK)),
				},
				{
					Status:  http.StatusNotFound,
					Message: ptr(http.StatusText(http.StatusNotFound)),
				},
				{
					Status:  http.StatusOK,
					Message: ptr(http.StatusText(http.StatusOK)),
				},
				{
					Status:  http.StatusOK,
					Message: ptr(http.StatusText(http.StatusOK)),
				},
				{
					Status:  http.StatusOK,
					Message: ptr(http.StatusText(http.StatusOK)),
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
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "ab12dcd8-bde0-4045-92dc-c4b27668d73a",
				"error": "Error with no payload"
			    }`),
			}},
			res: newAckResponse(false, []AckResponseItem{
				{
					Status:  http.StatusOK,
					Message: ptr(http.StatusText(http.StatusOK)),
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
			events: []AckRequest_Events_Item{{
				json.RawMessage(`{
				"action_id": "ab12dcd8-bde0-4045-92dc-c4b27668d73a",
				"error": "Error with payload",
				"payload": {"retry":true,"retry_attempt":1}
			    }`),
			}},
			res: newAckResponse(false, []AckResponseItem{
				{
					Status:  http.StatusOK,
					Message: ptr(http.StatusText(http.StatusOK)),
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

		logger := testlog.SetLogger(t)
		ack := &AckT{bulk: bulker}
		ack.invalidateAPIKeys(context.Background(), logger, out.ToRetireAPIKeyIds, skip)

		bulker.AssertExpectations(t)
	}
}

func TestInvalidateAPIKeysRemoteOutput(t *testing.T) {
	toRetire := []model.ToRetireAPIKeyIdsItems{{
		ID:     "toRetire1",
		Output: "remote1",
	}, {
		ID:     "toRetire11",
		Output: "remote1",
	}, {
		ID:     "toRetire2",
		Output: "remote2",
	}}

	bulker := ftesting.NewMockBulk()
	remoteBulker := ftesting.NewMockBulk()
	remoteBulker2 := ftesting.NewMockBulk()
	bulker.On("GetBulker", "remote1").Return(remoteBulker)
	bulker.On("GetBulker", "remote2").Return(remoteBulker2)

	remoteBulker.On("APIKeyInvalidate",
		context.Background(), []string{"toRetire1", "toRetire11"}).
		Return(nil)
	remoteBulker2.On("APIKeyInvalidate",
		context.Background(), []string{"toRetire2"}).
		Return(nil)

	logger := testlog.SetLogger(t)
	ack := &AckT{bulk: bulker}
	ack.invalidateAPIKeys(context.Background(), logger, toRetire, "")

	bulker.AssertExpectations(t)
	remoteBulker.AssertExpectations(t)
	remoteBulker2.AssertExpectations(t)
}

func TestInvalidateAPIKeysRemoteOutputReadFromPolicies(t *testing.T) {
	toRetire := []model.ToRetireAPIKeyIdsItems{{
		ID:     "toRetire1",
		Output: "remote1",
	}}

	remoteBulker := ftesting.NewMockBulk()
	remoteBulker.On("APIKeyInvalidate",
		context.Background(), []string{"toRetire1"}).
		Return(nil)

	bulkerFn := func(t *testing.T) *ftesting.MockBulk {
		m := ftesting.NewMockBulk()
		m.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
			Hits: []es.HitT{{
				Source: []byte(`{"data":{"outputs":{"remote1":{}}}}`),
			}},
		}}, nil).Once()

		m.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(remoteBulker, false, nil)
		m.On("GetBulker", "remote1").Return(nil)
		return m
	}

	bulker := bulkerFn(t)

	logger := testlog.SetLogger(t)
	ack := &AckT{bulk: bulker}
	ack.invalidateAPIKeys(context.Background(), logger, toRetire, "")

	bulker.AssertExpectations(t)
	remoteBulker.AssertExpectations(t)
}

func TestInvalidateAPIKeysRemoteOutputReadFromPoliciesNotFound(t *testing.T) {
	toRetire := []model.ToRetireAPIKeyIdsItems{{
		ID:     "toRetire1",
		Output: "remote1",
	}}

	remoteBulker := ftesting.NewMockBulk()

	bulkerFn := func(t *testing.T) *ftesting.MockBulk {
		m := ftesting.NewMockBulk()
		m.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{HitsT: es.HitsT{
			Hits: []es.HitT{},
		}}, nil).Once()

		m.On("GetBulker", "remote1").Return(nil)
		return m
	}

	bulker := bulkerFn(t)

	logger := testlog.SetLogger(t)
	ack := &AckT{bulk: bulker}
	ack.invalidateAPIKeys(context.Background(), logger, toRetire, "")

	bulker.AssertExpectations(t)
	remoteBulker.AssertExpectations(t)
}

func TestAckHandleUpgrade(t *testing.T) {
	tests := []struct {
		name   string
		event  UpgradeEvent
		bulker func(t *testing.T) *ftesting.MockBulk
		agent  *model.Agent
	}{{
		name:  "ok",
		event: UpgradeEvent{},
		bulker: func(t *testing.T) *ftesting.MockBulk {
			m := ftesting.NewMockBulk()
			m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(func(p []byte) bool {
				var body map[string]map[string]interface{}
				if err := json.Unmarshal(p, &body); err != nil {
					t.Fatal(err)
				}
				upgradeAttempts, ok := body["doc"]["upgrade_attempts"]
				return ok == true && upgradeAttempts == nil
			}), mock.Anything).Return(nil).Once()
			return m
		},
		agent: &model.Agent{
			ESDocument: model.ESDocument{Id: "ab12dcd8-bde0-4045-92dc-c4b27668d735"},
			Agent:      &model.AgentMetadata{Version: "8.0.0"},
		},
	}, {
		name:  "keep upgrade_attempts if upgrade_details is not nil",
		event: UpgradeEvent{},
		bulker: func(t *testing.T) *ftesting.MockBulk {
			m := ftesting.NewMockBulk()
			m.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(func(p []byte) bool {
				var body map[string]map[string]interface{}
				if err := json.Unmarshal(p, &body); err != nil {
					t.Fatal(err)
				}
				_, ok := body["doc"]["upgrade_attempts"]
				return ok == false
			}), mock.Anything).Return(nil).Once()
			return m
		},
		agent: &model.Agent{
			ESDocument:     model.ESDocument{Id: "ab12dcd8-bde0-4045-92dc-c4b27668d735"},
			Agent:          &model.AgentMetadata{Version: "8.0.0"},
			UpgradeDetails: &model.UpgradeDetails{},
		},
	}}
	cfg := &config.Server{
		Limits: config.ServerLimits{},
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

			err := ack.handleUpgrade(ctx, logger, tc.agent, tc.event)
			assert.NoError(t, err)
			bulker.AssertExpectations(t)
		})
	}
}

func TestValidateAckRequest(t *testing.T) {
	tests := []struct {
		name   string
		req    *http.Request
		cfg    *config.Server
		expErr error
		expAck *AckRequest
	}{
		{
			name: "Invalid Request",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`not a json`)),
			},
			cfg: &config.Server{
				Limits: config.ServerLimits{},
			},
			expErr: &BadRequestErr{msg: "unable to decode ack request", nextErr: errors.New("invalid character 'o' in literal null (expecting 'u')")},
			expAck: nil,
		},
	}
	logger := testlog.SetLogger(t)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wr := httptest.NewRecorder()
			ack := NewAckT(tc.cfg, nil, nil)
			ackRes, err := ack.validateRequest(logger, wr, tc.req)
			if tc.expErr == nil {
				assert.NoError(t, err)
			} else {
				// Asserting error messages prior to ErrorAs becuase ErrorAs modifies
				// the target error. If we assert error messages after calling ErrorAs
				// we will end up with false positives.
				assert.Equal(t, tc.expErr.Error(), err.Error())
				assert.ErrorAs(t, err, &tc.expErr)
			}
			assert.Equal(t, tc.expAck, ackRes)
		})
	}
}
