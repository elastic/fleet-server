// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"compress/flate"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	mockmonitor "github.com/elastic/fleet-server/v7/internal/pkg/monitor/mock"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testcache "github.com/elastic/fleet-server/v7/internal/pkg/testing/cache"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/hashicorp/go-version"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestConvertActionData(t *testing.T) {
	tests := []struct {
		name   string
		aType  ActionType
		raw    json.RawMessage
		expect Action_Data
		hasErr bool
	}{{
		name:   "nil input fails",
		aType:  CANCEL,
		raw:    nil,
		expect: Action_Data{},
		hasErr: true,
	}, {
		name:   "empty input succeeds",
		aType:  CANCEL,
		raw:    json.RawMessage(`{}`),
		expect: Action_Data{json.RawMessage(`{"target_id":""}`)},
		hasErr: false,
	}, {
		name:   "cancel action",
		aType:  CANCEL,
		raw:    json.RawMessage(`{"target_id":"target"}`),
		expect: Action_Data{json.RawMessage(`{"target_id":"target"}`)},
		hasErr: false,
	}, {
		name:   "input action",
		aType:  INPUTACTION,
		raw:    json.RawMessage(`{"key":"value"}`),
		expect: Action_Data{json.RawMessage(`{"key":"value"}`)},
		hasErr: false,
	}, {
		name:   "policy reassign action",
		aType:  POLICYREASSIGN,
		raw:    json.RawMessage(`{"policy_id":"policy"}`),
		expect: Action_Data{json.RawMessage(`{"policy_id":"policy"}`)},
		hasErr: false,
	}, {
		name:   "settings action",
		aType:  SETTINGS,
		raw:    json.RawMessage(`{"log_level":"error"}`),
		expect: Action_Data{json.RawMessage(`{"log_level":"error"}`)},
		hasErr: false,
	}, {
		name:   "upgrade action",
		aType:  UPGRADE,
		raw:    json.RawMessage(`{"source_uri":"https://localhost:8080","version":"1.2.3"}`),
		expect: Action_Data{json.RawMessage(`{"source_uri":"https://localhost:8080","version":"1.2.3"}`)},
		hasErr: false,
	}, {
		name:   "request diagnostics action",
		aType:  REQUESTDIAGNOSTICS,
		expect: Action_Data{},
		hasErr: false,
	}, {
		name:   "request diagnostics action empty data",
		aType:  REQUESTDIAGNOSTICS,
		raw:    json.RawMessage(`{}`),
		expect: Action_Data{json.RawMessage(`{}`)},
		hasErr: false,
	}, {
		name:   "request diagnostics with additional cpu metric",
		aType:  REQUESTDIAGNOSTICS,
		raw:    json.RawMessage(`{"additional_metrics": ["CPU"]}`),
		expect: Action_Data{json.RawMessage(`{"additional_metrics":["CPU"]}`)},
		hasErr: false,
	}, {
		name:   "unenroll action",
		aType:  UNENROLL,
		expect: Action_Data{},
		hasErr: false,
	}, {
		name:   "unknown action type",
		aType:  ActionType("UNKNOWN"),
		expect: Action_Data{},
		hasErr: true,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ad, err := convertActionData(tc.aType, tc.raw)
			if tc.hasErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expect, ad)
		})
	}
}

func TestConvertActions(t *testing.T) {
	tests := []struct {
		name    string
		actions []model.Action
		resp    []Action
		token   string
	}{{
		name:    "empty actions",
		actions: nil,
		resp:    []Action{},
		token:   "",
	}, {
		name:    "single action",
		actions: []model.Action{{ActionID: "1234", Type: "REQUEST_DIAGNOSTICS", Data: json.RawMessage(`{}`)}},
		resp: []Action{{
			AgentId: "agent-id",
			Id:      "1234",
			Type:    REQUESTDIAGNOSTICS,
			Data:    Action_Data{json.RawMessage(`{}`)},
		}},
		token: "",
	}, {
		name:    "single action signed",
		actions: []model.Action{{ActionID: "1234", Signed: &model.Signed{Data: "eyJAdGltZXN0YW==", Signature: "U6NOg4ssxpFV="}, Type: "REQUEST_DIAGNOSTICS", Data: json.RawMessage(`{}`)}},
		resp: []Action{{
			AgentId: "agent-id",
			Id:      "1234",
			Type:    REQUESTDIAGNOSTICS,
			Signed:  &ActionSignature{Data: "eyJAdGltZXN0YW==", Signature: "U6NOg4ssxpFV="},
			Data:    Action_Data{json.RawMessage(`{}`)},
		}},
		token: "",
	}, {name: "multiple actions",
		actions: []model.Action{
			{
				ActionID: "1234",
				Type:     "REQUEST_DIAGNOSTICS",
				Data:     json.RawMessage(`{}`),
			},
			{
				ActionID: "5678",
				Type:     "REQUEST_DIAGNOSTICS",
				Data:     json.RawMessage(`{}`),
				Signed:   &model.Signed{Data: "eyJAdGltZXN0YX==", Signature: "U6NOg4ssxpFQ="},
			},
		},
		resp: []Action{{
			AgentId: "agent-id",
			Id:      "1234",
			Type:    REQUESTDIAGNOSTICS,
			Data:    Action_Data{json.RawMessage(`{}`)},
		}, {
			AgentId: "agent-id",
			Id:      "5678",
			Signed:  &ActionSignature{Data: "eyJAdGltZXN0YX==", Signature: "U6NOg4ssxpFQ="},
			Type:    REQUESTDIAGNOSTICS,
			Data:    Action_Data{json.RawMessage(`{}`)},
		}},
		token: "",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			resp, token := convertActions(logger, "agent-id", tc.actions)
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
			Type:     "UPGRADE",
		}, {
			ActionID: "5678",
			Type:     "UNENROLL",
		}},
		resp: []model.Action{{
			ActionID: "1234",
			Type:     "UPGRADE",
		}, {
			ActionID: "5678",
			Type:     "UNENROLL",
		}},
	}, {
		name: "filter POLICY_CHANGE action",
		actions: []model.Action{{
			ActionID: "1234",
			Type:     "POLICY_CHANGE",
		}, {
			ActionID: "5678",
			Type:     "UNENROLL",
		}},
		resp: []model.Action{{
			ActionID: "5678",
			Type:     "UNENROLL",
		}},
	}, {
		name: "filter UPDATE_TAGS action",
		actions: []model.Action{{
			ActionID: "1234",
			Type:     "UPDATE_TAGS",
		}},
		resp: []model.Action{},
	}, {
		name: "filter FORCE_UNENROLL action",
		actions: []model.Action{{
			ActionID: "1234",
			Type:     "FORCE_UNENROLL",
		}},
		resp: []model.Action{},
	}, {
		name: "No type is filterd",
		actions: []model.Action{{
			ActionID: "1234",
		}},
		resp: []model.Action{},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			resp := filterActions(logger, "agent-id", tc.actions)
			assert.Equal(t, tc.resp, resp)
		})
	}
}

func TestResolveSeqNo(t *testing.T) {
	tests := []struct {
		name  string
		req   CheckinRequest
		agent *model.Agent
		resp  sqn.SeqNo
	}{{
		name: "empty ackToken",
		req: CheckinRequest{
			AckToken: new(string),
		},
		agent: &model.Agent{
			ActionSeqNo: []int64{sqn.UndefinedSeqNo},
		},
		resp: []int64{sqn.UndefinedSeqNo},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// setup mock CheckinT
			logger := testlog.SetLogger(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			verCon := mustBuildConstraints("8.0.0")
			cfg := &config.Server{}
			c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
			bc := checkin.NewBulk(nil)
			bulker := ftesting.NewMockBulk()
			pim := mockmonitor.NewMockMonitor()
			pm := policy.NewMonitor(bulker, pim, config.ServerLimits{PolicyLimit: config.Limit{Interval: 5 * time.Millisecond, Burst: 1}})
			ct := NewCheckinT(verCon, cfg, c, bc, pm, nil, nil, nil, nil)

			resp, _ := ct.resolveSeqNo(ctx, logger, tc.req, tc.agent)
			assert.Equal(t, tc.resp, resp)
		})
	}

}

func TestProcessUpgradeDetails(t *testing.T) {
	esd := model.ESDocument{Id: "doc-ID"}
	tests := []struct {
		name    string
		agent   *model.Agent
		details *UpgradeDetails
		bulk    func() *ftesting.MockBulk
		cache   func() *testcache.MockCache
		err     error
	}{{
		name:    "agent and checkin details are nil",
		agent:   &model.Agent{ESDocument: esd},
		details: nil,
		bulk: func() *ftesting.MockBulk {
			return ftesting.NewMockBulk()
		},
		cache: func() *testcache.MockCache {
			return testcache.NewMockCache()
		},
		err: nil,
	}, {
		name:    "agent has details checkin details are nil",
		agent:   &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}, UpgradeDetails: &model.UpgradeDetails{}},
		details: nil,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.MatchedBy(func(p []byte) bool {
				doc := struct {
					Doc map[string]interface{} `json:"doc"`
				}{}
				if err := json.Unmarshal(p, &doc); err != nil {
					t.Logf("bulk match unmarshal error: %v", err)
					return false
				}
				return doc.Doc[dl.FieldUpgradeDetails] == nil && doc.Doc[dl.FieldUpgradeStartedAt] == nil && doc.Doc[dl.FieldUpgradeStatus] == nil && doc.Doc[dl.FieldUpgradedAt] != ""
			}), mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			return testcache.NewMockCache()
		},
		err: nil,
	}, {
		name:    "upgrade requested action in cache",
		agent:   &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{ActionId: "test-action", State: UpgradeDetailsStateUPGREQUESTED},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: nil,
	}, {
		name:    "upgrade requested action not in cache",
		agent:   &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{ActionId: "test-action", State: UpgradeDetailsStateUPGREQUESTED},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Search", mock.Anything, dl.FleetActions, mock.Anything, mock.Anything).Return(
				&es.ResultT{
					HitsT: es.HitsT{
						Hits: []es.HitT{
							{Source: []byte(`{"action_id": "test-action"}`)},
						},
					},
				}, nil)
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, false)
			mCache.On("SetAction", mock.Anything)
			return mCache
		},
		err: nil,
	}, {
		name:    "upgrade requested action invalid",
		agent:   &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{ActionId: "test-action", State: UpgradeDetailsStateUPGREQUESTED},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Search", mock.Anything, dl.FleetActions, mock.Anything, mock.Anything).Return(&es.ResultT{}, es.ErrNotFound)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, false)
			return mCache
		},
		err: es.ErrNotFound,
	}, {
		name:  "upgrade scheduled action in cache",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGSCHEDULED,
			Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"scheduled_at":"2023-01-02T12:00:00Z"}`)},
		},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: nil,
	}, {
		name:  "upgrade scheduled action in cache invalid time",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGSCHEDULED,
			Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"scheduled_at":"2023:01:02T12:00:00Z"}`)},
		},
		bulk: func() *ftesting.MockBulk {
			return ftesting.NewMockBulk()
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: ErrInvalidUpgradeMetadata,
	}, {
		name:  "upgrade scheduled action in cache empty time",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGSCHEDULED,
			Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"scheduled_at":""}`)},
		},
		bulk: func() *ftesting.MockBulk {
			return ftesting.NewMockBulk()
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: ErrInvalidUpgradeMetadata,
	}, {
		name:  "upgrade scheduled action in cache no metadata",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGSCHEDULED,
		},
		bulk: func() *ftesting.MockBulk {
			return ftesting.NewMockBulk()
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: ErrInvalidUpgradeMetadata,
	}, {
		name:  "upgrade scheduled action in cache with additional metadata attribute",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGSCHEDULED,
			Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"scheduled_at":"2023-01-02T12:00:00Z","download_percent":12.3}`)},
		},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: nil,
	}, {
		name:  "upgrade downloading action in cache",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGDOWNLOADING,
			Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"download_percent":12.3}`)},
		},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: nil,
	}, {
		name:  "upgrade downloading action in cache no metadata",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGDOWNLOADING,
		},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: nil,
	}, {
		name:  "upgrade downloading action in cache wrong metadata attribute present",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGDOWNLOADING,
			Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"scheduled_at":"2023-01-02T12:00:00Z"}`)},
		},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: nil,
	}, {
		name:  "upgrade failed action in cache",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGFAILED,
			Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"error_msg":"failed"}`)},
		},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: nil,
	}, {
		name:  "upgrade failed action in cache empty error_msg",
		agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGFAILED,
			Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"error_msg":""}`)},
		},
		bulk: func() *ftesting.MockBulk {
			return ftesting.NewMockBulk()
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, true)
			return mCache
		},
		err: ErrInvalidUpgradeMetadata,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mBulk := tc.bulk()
			mCache := tc.cache()

			ct := &CheckinT{
				cache:  mCache,
				bulker: mBulk,
			}

			err := ct.processUpgradeDetails(context.Background(), tc.agent, tc.details)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.err)
			}
			mBulk.AssertExpectations(t)
			mCache.AssertExpectations(t)
		})
	}
}

func Test_CheckinT_writeResponse(t *testing.T) {
	tests := []struct {
		name       string
		req        *http.Request
		respHeader string
	}{{
		name:       "no compression",
		req:        &http.Request{},
		respHeader: "",
	}, {
		name: "with compression",
		req: &http.Request{
			Header: http.Header{
				"Accept-Encoding": []string{"gzip"},
			},
		},
		respHeader: "gzip",
	}}

	verCon := mustBuildConstraints("8.0.0")
	cfg := &config.Server{
		CompressionLevel:  flate.BestSpeed,
		CompressionThresh: 1,
	}

	ct := NewCheckinT(verCon, cfg, nil, nil, nil, nil, nil, nil, ftesting.NewMockBulk())

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wr := httptest.NewRecorder()
			err := ct.writeResponse(testlog.SetLogger(t), wr, test.req, &model.Agent{}, CheckinResponse{
				Action: "checkin",
			})
			resp := wr.Result()
			defer resp.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, test.respHeader, resp.Header.Get("Content-Encoding"))
		})
	}
}

func Benchmark_CheckinT_writeResponse(b *testing.B) {
	verCon := mustBuildConstraints("8.0.0")
	cfg := &config.Server{
		CompressionLevel:  flate.BestSpeed,
		CompressionThresh: 1,
	}
	ct := NewCheckinT(verCon, cfg, nil, nil, nil, nil, nil, nil, ftesting.NewMockBulk())

	logger := zerolog.Nop()
	req := &http.Request{
		Header: http.Header{
			"Accept-Encoding": []string{"gzip"},
		},
	}
	agent := &model.Agent{}
	resp := CheckinResponse{
		Action: "checkin",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ct.writeResponse(logger, httptest.NewRecorder(), req, agent, resp)
		require.NoError(b, err)
	}
}

func BenchmarkParallel_CheckinT_writeResponse(b *testing.B) {
	verCon := mustBuildConstraints("8.0.0")
	cfg := &config.Server{
		CompressionLevel:  flate.BestSpeed,
		CompressionThresh: 1,
	}
	ct := NewCheckinT(verCon, cfg, nil, nil, nil, nil, nil, nil, ftesting.NewMockBulk())

	logger := zerolog.Nop()
	req := &http.Request{
		Header: http.Header{
			"Accept-Encoding": []string{"gzip"},
		},
	}
	agent := &model.Agent{}
	resp := CheckinResponse{
		Action: "checkin",
	}

	b.ResetTimer()
	b.SetParallelism(100)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := ct.writeResponse(logger, httptest.NewRecorder(), req, agent, resp)
			require.NoError(b, err)
		}
	})
}

func mustBuildConstraints(verStr string) version.Constraints {
	con, err := BuildVersionConstraint(verStr)
	if err != nil {
		panic(err)
	}
	return con
}
