// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"context"
	"encoding/json"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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
		actions: []model.Action{{ActionID: "1234"}},
		resp: []Action{{
			AgentId: "agent-id",
			Id:      "1234",
			Data:    json.RawMessage(nil),
		}},
		token: "",
	}, {
		name:    "single action signed",
		actions: []model.Action{{ActionID: "1234", Signed: &model.Signed{Data: "eyJAdGltZXN0YW==", Signature: "U6NOg4ssxpFV="}}},
		resp: []Action{{
			AgentId: "agent-id",
			Id:      "1234",
			Data:    json.RawMessage(nil),
			Signed:  &ActionSignature{Data: "eyJAdGltZXN0YW==", Signature: "U6NOg4ssxpFV="},
		}},
		token: "",
	}, {name: "multiple actions",
		actions: []model.Action{
			{ActionID: "1234"},
			{ActionID: "5678", Signed: &model.Signed{Data: "eyJAdGltZXN0YX==", Signature: "U6NOg4ssxpFQ="}},
		},
		resp: []Action{{
			AgentId: "agent-id",
			Id:      "1234",
			Data:    json.RawMessage(nil),
		}, {
			AgentId: "agent-id",
			Id:      "5678",
			Data:    json.RawMessage(nil),
			Signed:  &ActionSignature{Data: "eyJAdGltZXN0YX==", Signature: "U6NOg4ssxpFQ="},
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
			pm := policy.NewMonitor(bulker, pim, 5*time.Millisecond)
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
		agent:   &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}, UpgradeDetails: json.RawMessage(`{"action_id":"test"}`)},
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
