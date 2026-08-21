// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
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

type mockPolicyMonitor struct {
	mock.Mock
}

func (m *mockPolicyMonitor) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockPolicyMonitor) Subscribe(agentID, policyID string, revIDX int64) (policy.Subscription, error) {
	args := m.Called(agentID, policyID, revIDX)
	return args.Get(0).(policy.Subscription), args.Error(1)
}

func (m *mockPolicyMonitor) Unsubscribe(sub policy.Subscription) error {
	args := m.Called(sub)
	return args.Error(0)
}

func (m *mockPolicyMonitor) LatestRev(ctx context.Context, id string) int64 {
	args := m.Called(ctx, id)
	return args.Get(0).(int64)
}

func (m *mockPolicyMonitor) GetPolicy(ctx context.Context, policyID string) (*model.Policy, error) {
	args := m.Called(ctx, policyID)
	p, _ := args.Get(0).(*model.Policy)
	return p, args.Error(1)
}

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
		name:   "settings action trace level",
		aType:  SETTINGS,
		raw:    json.RawMessage(`{"log_level":"trace"}`),
		expect: Action_Data{json.RawMessage(`{"log_level":"trace"}`)},
		hasErr: false,
	}, {
		name:   "upgrade action",
		aType:  UPGRADE,
		raw:    json.RawMessage(`{"sources":["https://localhost:8080"],"version":"1.2.3"}`),
		expect: Action_Data{json.RawMessage(`{"source_uri":"https://localhost:8080","sources":["https://localhost:8080"],"version":"1.2.3"}`)},
		hasErr: false,
	}, {
		name:   "upgrade action populates source uri from sources",
		aType:  UPGRADE,
		raw:    json.RawMessage(`{"sources":["https://first.example.com","https://second.example.com"],"version":"1.2.3"}`),
		expect: Action_Data{json.RawMessage(`{"source_uri":"https://first.example.com","sources":["https://first.example.com","https://second.example.com"],"version":"1.2.3"}`)},
		hasErr: false,
	}, {
		name:   "upgrade action populates sources from source uri",
		aType:  UPGRADE,
		raw:    json.RawMessage(`{"source_uri":"https://legacy.example.com","version":"1.2.3"}`),
		expect: Action_Data{json.RawMessage(`{"source_uri":"https://legacy.example.com","sources":["https://legacy.example.com"],"version":"1.2.3"}`)},
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
		name:   "migrate action - nil input fails",
		aType:  MIGRATE,
		raw:    nil,
		expect: Action_Data{},
		hasErr: true,
	}, {
		name:   "migrate action - missing required field",
		aType:  MIGRATE,
		raw:    json.RawMessage(`{}`),
		expect: Action_Data{json.RawMessage(`{"enrollment_token":"","target_uri":""}`)},
		hasErr: false,
	}, {
		name:   "migrate action",
		aType:  MIGRATE,
		raw:    json.RawMessage(`{"enrollment_token":"et","target_uri":"turi"}`),
		expect: Action_Data{json.RawMessage(`{"enrollment_token":"et","target_uri":"turi"}`)},
		hasErr: false,
	}, {
		name:   "privilege level change action - with data",
		aType:  PRIVILEGELEVELCHANGE,
		raw:    json.RawMessage(`{"unprivileged":true,"user_info":{"password":"1q2w3e","username":"demo"}}`),
		expect: Action_Data{json.RawMessage(`{"unprivileged":true,"user_info":{"password":"1q2w3e","username":"demo"}}`)},
		hasErr: false,
	}, {
		name:   "privilege level change action",
		aType:  PRIVILEGELEVELCHANGE,
		raw:    json.RawMessage(`{}`),
		expect: Action_Data{json.RawMessage(`{"unprivileged":false}`)},
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
	}, {
		name:    "upgrade action",
		actions: []model.Action{{ActionID: "1234", Type: "UPGRADE", Data: json.RawMessage(`{"sources":["https://first.example.com","https://second.example.com"],"version":"9.6.0"}`)}},
		resp: []Action{{
			AgentId: "agent-id",
			Id:      "1234",
			Type:    UPGRADE,
			Data:    Action_Data{json.RawMessage(`{"source_uri":"https://first.example.com","sources":["https://first.example.com","https://second.example.com"],"version":"9.6.0"}`)},
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
			{
				ActionID: "91011",
				Type:     "MIGRATE",
				Data:     json.RawMessage(`{"enrollment_token":"et","policy_id":"pid","target_uri":"turi"}`),
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
		}, {
			AgentId: "agent-id",
			Id:      "91011",
			Type:    MIGRATE,
			Data:    Action_Data{json.RawMessage(`{"enrollment_token":"et","target_uri":"turi"}`)},
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
			ctx := t.Context()
			verCon := mustBuildConstraints("8.0.0")
			cfg := &config.Server{}
			c, _ := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
			bc := checkin.NewBulk(nil)
			pm := &mockPolicyMonitor{}
			ct, err := NewCheckinT(verCon, cfg, c, bc, pm, nil, nil, nil)
			assert.NoError(t, err)

			resp, _ := ct.resolveSeqNo(ctx, logger, tc.req, tc.agent)
			assert.Equal(t, tc.resp, resp)
			pm.AssertExpectations(t)
		})
	}

}

func TestProcessUpgradeDetails(t *testing.T) {
	esd := model.ESDocument{Id: "doc-ID"}
	doc := bulk.UpdateFields{
		dl.FieldUpgradeDetails: &UpgradeDetails{
			ActionId: "test-action",
			State:    UpgradeDetailsStateUPGWATCHING,
		},
		dl.FieldUpgradeAttempts: nil,
	}
	body, err := doc.Marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
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
					Doc map[string]any `json:"doc"`
				}{}
				if err := json.Unmarshal(p, &doc); err != nil {
					t.Logf("bulk match unmarshal error: %v", err)
					return false
				}
				return doc.Doc[dl.FieldUpgradeDetails] == nil && doc.Doc[dl.FieldUpgradeStartedAt] == nil && doc.Doc[dl.FieldUpgradedAt] != ""
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
		name:    "upgrade requested action not found",
		agent:   &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{ActionId: "test-action", State: UpgradeDetailsStateUPGREQUESTED},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Search", mock.Anything, dl.FleetActions, mock.Anything, mock.Anything).Return(&es.ResultT{}, es.ErrNotFound)
			mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, false)
			return mCache
		},
		err: nil,
	}, {
		name:    "upgrade requested action failed to fetch",
		agent:   &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
		details: &UpgradeDetails{ActionId: "test-action", State: UpgradeDetailsStateUPGREQUESTED},
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			mBulk.On("Search", mock.Anything, dl.FleetActions, mock.Anything, mock.Anything).Return(&es.ResultT{}, es.ErrTimeout)
			return mBulk
		},
		cache: func() *testcache.MockCache {
			mCache := testcache.NewMockCache()
			mCache.On("GetAction", "test-action").Return(model.Action{}, false)
			return mCache
		},
		err: es.ErrTimeout,
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
	},
		{
			name:  "upgrade downloading action in cache, download rate in bytes",
			agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
			details: &UpgradeDetails{
				ActionId: "test-action",
				State:    UpgradeDetailsStateUPGDOWNLOADING,
				Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"download_percent":12.3, "download_rate": 1000000}`)},
			},
			bulk: func() *ftesting.MockBulk {
				mBulk := ftesting.NewMockBulk()
				mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.MatchedBy(func(p []byte) bool {
					// match doc that gets sent to ES
					doc := struct {
						Doc struct {
							UpgradeDetails struct {
								Metadata UpgradeMetadataDownloading `json:"metadata"`
							} `json:"upgrade_details"`
						} `json:"doc"`
					}{}
					err := json.Unmarshal(p, &doc)
					if err != nil {
						t.Logf("Unmarshal update body failed: %v", err)
						return false
					}
					require.Equal(t, float64(12.3), doc.Doc.UpgradeDetails.Metadata.DownloadPercent, "download_percent does not match")
					require.Equal(t, float64(1000000), *doc.Doc.UpgradeDetails.Metadata.DownloadRate, "download_rate does not match")
					return true
				}), mock.Anything, mock.Anything).Return(nil)
				return mBulk
			},
			cache: func() *testcache.MockCache {
				mCache := testcache.NewMockCache()
				mCache.On("GetAction", "test-action").Return(model.Action{}, true)
				return mCache
			},
			err: nil,
		}, {
			name:  "upgrade downloading action in cache, download rate in Human MB",
			agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}},
			details: &UpgradeDetails{
				ActionId: "test-action",
				State:    UpgradeDetailsStateUPGDOWNLOADING,
				Metadata: &UpgradeDetails_Metadata{json.RawMessage(`{"download_percent":12.3, "download_rate": "1MBps"}`)},
			},
			bulk: func() *ftesting.MockBulk {
				mBulk := ftesting.NewMockBulk()
				mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.MatchedBy(func(p []byte) bool {
					// match doc that gets sent to ES
					doc := struct {
						Doc struct {
							UpgradeDetails struct {
								Metadata UpgradeMetadataDownloading `json:"metadata"`
							} `json:"upgrade_details"`
						} `json:"doc"`
					}{}
					t.Logf("Attempting to match %s", string(p))
					err := json.Unmarshal(p, &doc)
					if err != nil {
						t.Logf("Unmarshal update body failed: %v", err)
						return false
					}
					require.Equal(t, float64(12.3), doc.Doc.UpgradeDetails.Metadata.DownloadPercent, "download_percent does not match")
					require.Equal(t, float64(1000000), *doc.Doc.UpgradeDetails.Metadata.DownloadRate, "download_rate does not match")
					return true
				}), mock.Anything, mock.Anything).Return(nil)
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
		}, {
			name:  "clear upgrade attempts when watching",
			agent: &model.Agent{ESDocument: esd, Agent: &model.AgentMetadata{ID: "test-agent"}, UpgradeAttempts: make([]string, 0)},
			details: &UpgradeDetails{
				ActionId: "test-action",
				State:    UpgradeDetailsStateUPGWATCHING,
			},
			bulk: func() *ftesting.MockBulk {
				mBulk := ftesting.NewMockBulk()
				mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", body, mock.Anything, mock.Anything).Return(nil)
				return mBulk
			},
			cache: func() *testcache.MockCache {
				mCache := testcache.NewMockCache()
				mCache.On("GetAction", "test-action").Return(model.Action{}, true)
				return mCache
			},
			err: nil,
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

	ct, err := NewCheckinT(verCon, cfg, nil, nil, nil, nil, nil, ftesting.NewMockBulk())
	require.NoError(t, err)

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
	ct, err := NewCheckinT(verCon, cfg, nil, nil, nil, nil, nil, ftesting.NewMockBulk())
	require.NoError(b, err)

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
	ct, err := NewCheckinT(verCon, cfg, nil, nil, nil, nil, nil, ftesting.NewMockBulk())
	require.NoError(b, err)

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

func TestCalcUnhealthyReason(t *testing.T) {
	tests := []struct {
		name            string
		components      []model.ComponentsItems
		unhealthyReason []string
	}{{
		name: "healthy",
		components: []model.ComponentsItems{{
			Status: "HEALTHY",
			Units: []model.UnitsItems{{
				Status: "HEALTHY", Type: "input",
			}},
		}},
		unhealthyReason: []string{},
	}, {
		name: "input",
		components: []model.ComponentsItems{{
			Status: "FAILED",
			Units: []model.UnitsItems{{
				Status: "FAILED", Type: "input",
			}},
		}},
		unhealthyReason: []string{"input"},
	},
		{
			name: "output",
			components: []model.ComponentsItems{{
				Status: "DEGRADED",
				Units: []model.UnitsItems{{
					Status: "HEALTHY", Type: "input",
				},
					{
						Status: "DEGRADED", Type: "output",
					}},
			}},
			unhealthyReason: []string{"output"},
		},
		{
			name: "other",
			components: []model.ComponentsItems{{
				Status: "DEGRADED",
				Units:  []model.UnitsItems{},
			}},
			unhealthyReason: []string{"other"},
		},
		{
			name: "input,output in one component",
			components: []model.ComponentsItems{{
				Status: "DEGRADED",
				Units: []model.UnitsItems{{
					Status: "FAILED", Type: "input",
				},
					{
						Status: "DEGRADED", Type: "output",
					}},
			}},
			unhealthyReason: []string{"input", "output"},
		},
		{
			name: "input,output in different components",
			components: []model.ComponentsItems{{
				Status: "DEGRADED",
				Units: []model.UnitsItems{
					{
						Status: "DEGRADED", Type: "input",
					}},
			},
				{
					Status: "FAILED",
					Units: []model.UnitsItems{{
						Status: "FAILED", Type: "output",
					}},
				}},
			unhealthyReason: []string{"input", "output"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unhealthyReason := calcUnhealthyReason(tc.components)
			assert.Equal(t, tc.unhealthyReason, unhealthyReason)
		})
	}
}

func TestParseComponents(t *testing.T) {
	var unhealthyReasonNil []string
	degradedInputReqComponents := json.RawMessage(`[{"status":"DEGRADED","units":[{"status":"DEGRADED","type":"input"}]}]`)
	tests := []struct {
		name            string
		agent           *model.Agent
		req             *CheckinRequest
		outComponents   []byte
		unhealthyReason *[]string
		err             error
	}{{
		name:            "unchanged components healthy",
		agent:           &model.Agent{},
		req:             &CheckinRequest{},
		outComponents:   nil,
		unhealthyReason: &unhealthyReasonNil,
		err:             nil,
	},
		{
			name: "unchanged components unhealthy",
			agent: &model.Agent{
				LastCheckinStatus: FailedStatus,
			},
			req:             &CheckinRequest{},
			outComponents:   nil,
			unhealthyReason: &[]string{"other"},
			err:             nil,
		},
		{
			name: "unchanged components",
			agent: &model.Agent{
				LastCheckinStatus: FailedStatus,
				UnhealthyReason:   []string{"input"},
				Components: requireMarshalJSON(t, []model.ComponentsItems{{
					Status: "DEGRADED",
					Units: []model.UnitsItems{{
						Status: "DEGRADED", Type: "input",
					}},
				}}),
			},
			req: &CheckinRequest{
				Components: degradedInputReqComponents,
			},
			outComponents:   nil,
			unhealthyReason: &[]string{"input"},
			err:             nil,
		},
		{
			name: "changed components",
			agent: &model.Agent{
				LastCheckinStatus: "online",
				UnhealthyReason:   nil,
				Components: requireMarshalJSON(t, []model.ComponentsItems{{
					Status: "HEALTHY",
					Units: []model.UnitsItems{{
						Status: "HEALTHY", Type: "input",
					}},
				}}),
			},
			req: &CheckinRequest{
				Status:     "DEGRADED",
				Components: degradedInputReqComponents,
			},
			outComponents:   degradedInputReqComponents,
			unhealthyReason: &[]string{"input"},
			err:             nil,
		}, {
			name: "bad stored components",
			agent: &model.Agent{
				LastCheckinStatus: "online",
				UnhealthyReason:   nil,
				Components:        requireMarshalJSON(t, "string stored in components incorrectly"),
			},
			req: &CheckinRequest{
				Status:     "DEGRADED",
				Components: degradedInputReqComponents,
			},
			outComponents:   degradedInputReqComponents,
			unhealthyReason: &[]string{"input"},
			err:             nil,
		}, {
			name: "invalid JSON ignored",
			agent: &model.Agent{
				LastCheckinStatus: "online",
				UnhealthyReason:   nil,
				Components:        json.RawMessage("{s"),
			},
			req: &CheckinRequest{
				Status:     "DEGRADED",
				Components: degradedInputReqComponents,
			},
			outComponents:   degradedInputReqComponents,
			unhealthyReason: &[]string{"input"},
			err:             nil,
		}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			outComponents, unhealthyReason, err := parseComponents(logger, tc.agent, tc.req)
			assert.Equal(t, tc.outComponents, outComponents)
			assert.Equal(t, tc.unhealthyReason, unhealthyReason)
			assert.Equal(t, tc.err, err)
		})
	}
}

func requireMarshalJSON(t *testing.T, obj any) json.RawMessage {
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	return data
}

func TestIsInvalidAPIKeyErr(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{name: "ErrAPIKeyNotFound", err: apikey.ErrAPIKeyNotFound, expected: true},
		{name: "ErrUnauthorized", err: apikey.ErrUnauthorized, expected: true},
		{name: "ErrAPIKeyNotEnabled", err: ErrAPIKeyNotEnabled, expected: true},
		{name: "ErrAgentInactive", err: ErrAgentInactive, expected: true},
		{name: "wrapped ErrAPIKeyNotFound", err: fmt.Errorf("outer: %w", apikey.ErrAPIKeyNotFound), expected: true},
		{name: "wrapped ErrAgentInactive", err: fmt.Errorf("outer: %w", ErrAgentInactive), expected: true},
		{name: "ErrNoAuthHeader", err: apikey.ErrNoAuthHeader, expected: false},
		{name: "ErrMalformedHeader", err: apikey.ErrMalformedHeader, expected: false},
		{name: "ErrAgentCorrupted", err: ErrAgentCorrupted, expected: false},
		{name: "ErrAgentIdentity", err: ErrAgentIdentity, expected: false},
		{name: "generic error", err: errors.New("some other error"), expected: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isInvalidAPIKeyErr(tc.err))
		})
	}
}

func TestWriteEmptyPolicyChangeResponse(t *testing.T) {
	verCon := mustBuildConstraints("8.0.0")
	cfg := &config.Server{}
	ct, err := NewCheckinT(verCon, cfg, nil, nil, nil, nil, nil, ftesting.NewMockBulk())
	require.NoError(t, err)

	agentID := "test-agent-id"
	wr := httptest.NewRecorder()
	logger := testlog.SetLogger(t)

	err = ct.writeEmptyPolicyChangeResponse(logger, wr, agentID)
	require.NoError(t, err)

	resp := wr.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var checkinResp CheckinResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&checkinResp))

	assert.Equal(t, "checkin", checkinResp.Action)
	require.Len(t, checkinResp.Actions, 1)

	action := checkinResp.Actions[0]
	assert.Equal(t, agentID, action.AgentId)
	assert.Equal(t, POLICYCHANGE, action.Type)
	assert.NotEmpty(t, action.Id)
	assert.NotEmpty(t, action.CreatedAt)

	pc, err := action.Data.AsActionPolicyChange()
	require.NoError(t, err)
	assert.Empty(t, pc.Policy.Inputs)
}

// TestHandleInvalidAPIKey_Escalation verifies the three-step state machine:
//
//	1st invalid checkin → POLICY_CHANGE
//	2nd invalid checkin → UNENROLL
//	3rd+ invalid checkin → original 401 error
//	after 1 hour → state resets
func TestHandleInvalidAPIKey_Escalation(t *testing.T) {
	verCon := mustBuildConstraints("8.0.0")
	cfg := &config.Server{}
	ct, err := NewCheckinT(verCon, cfg, nil, nil, nil, nil, nil, ftesting.NewMockBulk())
	require.NoError(t, err)

	const agentID = "escalation-agent"
	logger := testlog.SetLogger(t)
	origErr := apikey.ErrUnauthorized

	call := func() (ActionType, error) {
		wr := httptest.NewRecorder()
		herr := ct.handleInvalidAPIKey(logger, wr, agentID, origErr)
		if herr != nil {
			return "", herr
		}
		var resp CheckinResponse
		require.NoError(t, json.NewDecoder(wr.Body).Decode(&resp))
		require.Len(t, resp.Actions, 1)
		return resp.Actions[0].Type, nil
	}

	// 1st call → POLICY_CHANGE
	actionType, err := call()
	require.NoError(t, err)
	assert.Equal(t, POLICYCHANGE, actionType)

	// 2nd call → UNENROLL
	actionType, err = call()
	require.NoError(t, err)
	assert.Equal(t, UNENROLL, actionType)

	// 3rd call → original error (401)
	_, err = call()
	assert.ErrorIs(t, err, origErr)

	// 4th call → still original error
	_, err = call()
	assert.ErrorIs(t, err, origErr)

	// Simulate state expiry by backdating firstSeen.
	state, ok := ct.invalidKeyStates.Load(agentID)
	require.True(t, ok)
	state.firstSeen = time.Now().Add(-(invalidKeyStateReset + time.Second))
	ct.invalidKeyStates.Store(agentID, state)

	// After reset → back to POLICY_CHANGE
	actionType, err = call()
	require.NoError(t, err)
	assert.Equal(t, POLICYCHANGE, actionType)
}

// makeAPIKeyAuthHeader returns an Authorization header value for the given key id and secret.
func makeAPIKeyAuthHeader(id, secret string) string {
	token := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	return "ApiKey " + token
}

func TestHandleCheckin_GracefulForceUnenroll(t *testing.T) {
	const agentID = "test-agent-id"

	tests := []struct {
		name        string
		authErr     error
		flagEnabled bool
		wantStatus  int
		wantAction  ActionType
	}{
		{
			name:        "flag enabled, ErrAPIKeyNotFound returns POLICY_CHANGE on first occurrence",
			authErr:     apikey.ErrAPIKeyNotFound,
			flagEnabled: true,
			wantStatus:  http.StatusOK,
			wantAction:  POLICYCHANGE,
		},
		{
			name:        "flag enabled, ErrUnauthorized returns POLICY_CHANGE on first occurrence",
			authErr:     apikey.ErrUnauthorized,
			flagEnabled: true,
			wantStatus:  http.StatusOK,
			wantAction:  POLICYCHANGE,
		},
		{
			name:        "flag enabled, ErrAPIKeyNotEnabled returns POLICY_CHANGE on first occurrence",
			authErr:     ErrAPIKeyNotEnabled,
			flagEnabled: true,
			wantStatus:  http.StatusOK,
			wantAction:  POLICYCHANGE,
		},
		{
			name:        "flag disabled, ErrAPIKeyNotFound returns 401",
			authErr:     apikey.ErrAPIKeyNotFound,
			flagEnabled: false,
			wantStatus:  http.StatusUnauthorized,
		},
		{
			name:        "flag enabled, ErrNoAuthHeader is not intercepted",
			authErr:     apikey.ErrNoAuthHeader,
			flagEnabled: true,
			wantStatus:  http.StatusUnauthorized,
		},
	}

	verCon := mustBuildConstraints("8.0.0")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Server{
				Features: config.FeatureFlags{
					GracefulForceUnenroll: config.GracefulForceUnenrollConfig{
						Enabled: tc.flagEnabled,
					},
				},
			}

			mCache := testcache.NewMockCache()
			mBulk := ftesting.NewMockBulk()

			var req *http.Request
			if errors.Is(tc.authErr, apikey.ErrNoAuthHeader) {
				// no Authorization header — triggers ErrNoAuthHeader before any bulker call
				req = httptest.NewRequest(http.MethodPost, "/", nil)
			} else if errors.Is(tc.authErr, ErrAPIKeyNotEnabled) {
				// ErrAPIKeyNotEnabled is produced by authAPIKey after APIKeyAuth returns
				// a disabled key (Enabled: false, nil error). SetAPIKey is then called
				// to update the cache before the error is surfaced.
				req = httptest.NewRequest(http.MethodPost, "/", nil)
				req.Header.Set("Authorization", makeAPIKeyAuthHeader("key-id", "key-secret"))
				mCache.On("ValidAPIKey", mock.Anything).Return(false)
				mBulk.On("APIKeyAuth", mock.Anything, mock.Anything).Return(&bulk.SecurityInfo{Enabled: false}, nil)
				mCache.On("SetAPIKey", mock.Anything, false)
			} else {
				req = httptest.NewRequest(http.MethodPost, "/", nil)
				req.Header.Set("Authorization", makeAPIKeyAuthHeader("key-id", "key-secret"))
				mCache.On("ValidAPIKey", mock.Anything).Return(false)
				mBulk.On("APIKeyAuth", mock.Anything, mock.Anything).Return((*bulk.SecurityInfo)(nil), tc.authErr)
			}

			ct, err := NewCheckinT(verCon, cfg, mCache, nil, nil, nil, nil, mBulk)
			require.NoError(t, err)

			logger := testlog.SetLogger(t)
			wr := httptest.NewRecorder()

			handleErr := ct.handleCheckin(logger, wr, req, agentID, "elastic-agent/8.0.0")

			if tc.wantStatus == http.StatusOK {
				// On success the handler writes the response itself and returns nil.
				require.NoError(t, handleErr)
				resp := wr.Result()
				defer resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode)

				var checkinResp CheckinResponse
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&checkinResp))
				require.Len(t, checkinResp.Actions, 1)
				assert.Equal(t, tc.wantAction, checkinResp.Actions[0].Type)
				assert.Equal(t, agentID, checkinResp.Actions[0].AgentId)
				assert.NotEmpty(t, checkinResp.Actions[0].Id)
			} else {
				// On 401 the handler returns the error; the API layer writes the status.
				require.Error(t, handleErr)
				assert.ErrorIs(t, handleErr, tc.authErr)
			}

			mBulk.AssertExpectations(t)
			mCache.AssertExpectations(t)
		})
	}
}

func TestValidateCheckinRequest(t *testing.T) {
	verCon := mustBuildConstraints("8.0.0")

	tests := []struct {
		name     string
		req      *http.Request
		cfg      *config.Server
		expErr   error
		expValid validatedCheckin
	}{
		{
			name: "Invalid JSON",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"invalidJson":}`)),
			},
			expErr: &BadRequestErr{msg: "unable to decode checkin request", nextErr: errors.New("invalid character '}' looking for beginning of value")},
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{},
		},
		{
			name: "Missing checkin status",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"validJson": "test"}`)),
			},
			expErr: &BadRequestErr{msg: "checkin status missing"},
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{},
		},
		{
			name: "Poll Timeout Parsing Error",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"validJson": "test", "status": "test", "poll_timeout": "not a timeout", "message": "test message"}`)),
			},
			expErr: &BadRequestErr{msg: "poll_timeout cannot be parsed as duration", nextErr: errors.New("time: invalid duration \"not a timeout\"")},
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{},
		},
		{
			name: "local metadata has fips attribute",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"status": "online", "message": "test message", "local_metadata": {"elastic": {"agent": {"id": "testid", "fips": true}}}}`)),
			},
			expErr: nil,
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{
				rawMeta:               []byte(`{"elastic": {"agent": {"id": "testid", "fips": true}}}`),
				rawAvailableRollbacks: []byte(`[]`),
			},
		},
		{
			name: "Available rollbacks are correctly parsed",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"validJson": "test", "status": "test", "message": "test message", "upgrade":{ "rollbacks": [{"version": "1.2.3-SNAPSHOT", "valid_until": "2025-11-27T15:12:44Z"}]}}`)),
			},
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expErr: nil,
			expValid: validatedCheckin{
				rawAvailableRollbacks: []byte(`[{"version": "1.2.3-SNAPSHOT", "valid_until": "2025-11-27T15:12:44Z"}]`),
			},
		},
		{
			name: "Available rollbacks are incorrectly formatted (string instead of array): no error returned but the rawAvailableRollbacks are set to nil",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"validJson": "test", "status": "test", "message": "test message", "upgrade":{"rollbacks": "foobar"}}`)),
			},
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expErr: nil,
			expValid: validatedCheckin{
				rawAvailableRollbacks: nil,
			},
		},
		{
			name: "gzip-compressed request body is decompressed before JSON decoding",
			req: func() *http.Request {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				_, _ = gz.Write([]byte(`{"status": "online", "message": "test message"}`))
				_ = gz.Close()
				return &http.Request{
					Header: http.Header{"Content-Encoding": []string{"gzip"}},
					Body:   io.NopCloser(&buf),
				}
			}(),
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expErr: nil,
			expValid: validatedCheckin{
				rawAvailableRollbacks: []byte(`[]`),
			},
		},
		{
			name: "invalid gzip request body returns bad request error",
			req: &http.Request{
				Header: http.Header{"Content-Encoding": []string{"gzip"}},
				Body:   io.NopCloser(strings.NewReader(`not gzip data`)),
			},
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expErr:   &BadRequestErr{msg: "unable to create gzip reader for request body", nextErr: gzip.ErrHeader},
			expValid: validatedCheckin{},
		},
		{
			name: "gzip compressed request body exceeds max agent doc size limit",
			req: func() *http.Request {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				_, _ = gz.Write([]byte(`{"status": "online", "message": "`))
				_, _ = gz.Write(bytes.Repeat([]byte("a"), 1024))
				_, _ = gz.Write([]byte(`"}`))
				_ = gz.Close()
				return &http.Request{
					Header: http.Header{"Content-Encoding": []string{"gzip"}},
					Body:   io.NopCloser(&buf),
				}
			}(),
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody:             512, // compressed body is lower than doc size
						MaxBodyDecompressed: 1024,
					},
				},
			},
			expErr: &BadRequestErr{msg: "unable to decode checkin request", nextErr: &http.MaxBytesError{Limit: 1024}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkin, err := NewCheckinT(verCon, tc.cfg, nil, nil, nil, nil, nil, nil)
			assert.NoError(t, err)
			wr := httptest.NewRecorder()
			logger := testlog.SetLogger(t)
			valid, err := checkin.validateRequest(logger, wr, tc.req, time.Time{}, &model.Agent{LocalMetadata: json.RawMessage(`{}`)})
			if tc.expErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, tc.expValid.rawMeta, valid.rawMeta)
				if tc.expValid.rawAvailableRollbacks == nil {
					assert.Nil(t, valid.rawAvailableRollbacks)
				} else {
					assert.JSONEq(t, string(tc.expValid.rawAvailableRollbacks), string(valid.rawAvailableRollbacks))
				}
			} else {
				// Asserting error messages prior to ErrorAs becuase ErrorAs modifies
				// the target error. If we assert error messages after calling ErrorAs
				// we will end up with false positives.
				assert.Equal(t, tc.expErr.Error(), err.Error())
				assert.ErrorAs(t, err, &tc.expErr)
			}
		})
	}
}

func TestProcessPolicyDetails(t *testing.T) {
	policyID := "policy-id"
	revIDX2 := int64(2)
	tests := []struct {
		name             string
		agent            *model.Agent
		req              *CheckinRequest
		getPolicyMonitor func() *mockPolicyMonitor
		revIDX           int64
		returnsOpts      bool
		err              error
	}{{
		name: "request has no policy details",
		agent: &model.Agent{
			PolicyRevisionIdx: 1,
		},
		req: &CheckinRequest{},
		getPolicyMonitor: func() *mockPolicyMonitor {
			return &mockPolicyMonitor{}
		},
		revIDX:      1,
		returnsOpts: false,
		err:         nil,
	}, {
		name: "policy reassign detected",
		agent: &model.Agent{
			Agent: &model.AgentMetadata{
				ID: "agent-id",
			},
			PolicyID:          "new-policy-id",
			AgentPolicyID:     policyID,
			PolicyRevisionIdx: 2,
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		getPolicyMonitor: func() *mockPolicyMonitor {
			return &mockPolicyMonitor{}
		},
		revIDX:      0,
		returnsOpts: false,
		err:         nil,
	}, {
		name: "revision updated",
		agent: &model.Agent{
			Agent: &model.AgentMetadata{
				ID: "agent-id",
			},
			PolicyID:          policyID,
			AgentPolicyID:     policyID,
			PolicyRevisionIdx: 1,
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		getPolicyMonitor: func() *mockPolicyMonitor {
			pm := &mockPolicyMonitor{}
			pm.On("LatestRev", mock.Anything, policyID).Return(int64(2)).Once()
			return pm
		},
		revIDX:      2,
		returnsOpts: true,
		err:         nil,
	}, {
		name: "checkin revision is greater than the policy's latest revision",
		agent: &model.Agent{
			Agent: &model.AgentMetadata{
				ID: "agent-id",
			},
			PolicyID:          policyID,
			AgentPolicyID:     policyID,
			PolicyRevisionIdx: 1,
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		getPolicyMonitor: func() *mockPolicyMonitor {
			pm := &mockPolicyMonitor{}
			pm.On("LatestRev", mock.Anything, policyID).Return(int64(1)).Once()
			return pm
		},
		revIDX:      0,
		returnsOpts: true,
		err:         nil,
	}, {
		name: "agent_policy_id has changed",
		agent: &model.Agent{
			Agent: &model.AgentMetadata{
				ID: "agent-id",
			},
			PolicyID:          policyID,
			AgentPolicyID:     "old-policy-id",
			PolicyRevisionIdx: 1,
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		getPolicyMonitor: func() *mockPolicyMonitor {
			pm := &mockPolicyMonitor{}
			pm.On("LatestRev", mock.Anything, policyID).Return(int64(2)).Once()
			return pm
		},
		revIDX:      2,
		returnsOpts: true,
		err:         nil,
	}, {
		name: "agent does not have agent_policy_id present",
		agent: &model.Agent{
			Agent: &model.AgentMetadata{
				ID: "agent-id",
			},
			PolicyID:          policyID,
			PolicyRevisionIdx: 2,
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		getPolicyMonitor: func() *mockPolicyMonitor {
			pm := &mockPolicyMonitor{}
			pm.On("LatestRev", mock.Anything, policyID).Return(int64(2)).Once()
			return pm
		},
		revIDX:      2,
		returnsOpts: true,
		err:         nil,
	}, {
		name: "details present with no changes from agent doc",
		agent: &model.Agent{
			Agent: &model.AgentMetadata{
				ID: "agent-id",
			},
			AgentPolicyID:     policyID,
			PolicyID:          policyID,
			PolicyRevisionIdx: revIDX2,
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		getPolicyMonitor: func() *mockPolicyMonitor {
			pm := &mockPolicyMonitor{}
			pm.On("LatestRev", mock.Anything, policyID).Return(int64(2)).Once()
			return pm
		},
		revIDX:      2,
		returnsOpts: false,
		err:         nil,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			pm := tc.getPolicyMonitor()
			checkin := &CheckinT{
				cfg:    &config.Server{},
				bulker: ftesting.NewMockBulk(),
				pm:     pm,
			}

			revIDX, opts, err := checkin.processPolicyDetails(t.Context(), logger, tc.agent, tc.req)
			assert.Equal(t, tc.revIDX, revIDX)
			if tc.returnsOpts {
				assert.NotEmpty(t, opts)
			} else {
				assert.Empty(t, opts)
			}
			if tc.err != nil {
				assert.ErrorIs(t, tc.err, err)
			} else {
				assert.NoError(t, err)
			}
			pm.AssertExpectations(t)
		})
	}

	t.Run("IgnoreCheckinPolicyID flag is set", func(t *testing.T) {
		logger := testlog.SetLogger(t)
		checkin := &CheckinT{
			cfg: &config.Server{
				Features: config.FeatureFlags{
					IgnoreCheckinPolicyID: true,
				},
			},
		}
		revIDX, opts, err := checkin.processPolicyDetails(t.Context(), logger,
			&model.Agent{
				PolicyID:          policyID,
				PolicyRevisionIdx: 1,
			},
			&CheckinRequest{
				AgentPolicyId:     &policyID,
				PolicyRevisionIdx: &revIDX2,
			},
		)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), revIDX)
		assert.Empty(t, opts)
	})
}

// TestProcessPolicyRemoteESServiceTokenSecretPaths ensures secret_path does not
// contain service_token for remote ES output as they are stripped before sending the policy to the agents

func TestProcessPolicyRemoteESServiceTokenSecretPaths(t *testing.T) {
	logger := testlog.SetLogger(t)

	const policyPayload = `{
  "id": "remote-with-secrets",
  "revision": 1,
  "outputs": {
    "default": {
      "type": "elasticsearch",
      "hosts": ["https://local.es.example:443"]
    },
    "OUTPUT_ID": {
      "type": "remote_elasticsearch",
      "hosts": ["https://remote.es.example:443"],
      "service_token": null,
      "secrets": {
        "service_token": {"id": "SERVICE_TOKEN_ID"},
        "ssl": {"key": {"id": "SSL_KEY_ID"}}
      }
    }
  },
  "output_permissions": {
    "default": {
      "_fallback": {
        "cluster": ["monitor"],
        "indices": [{"names": ["logs-*", "metrics-*"], "privileges": ["auto_configure", "create_doc"]}]
      }
    },
    "OUTPUT_ID": {
      "_fallback": {
        "cluster": ["monitor"],
        "indices": [{"names": ["logs-*", "metrics-*"], "privileges": ["auto_configure", "create_doc"]}]
      }
    }
  },
  "inputs": [],
  "secret_references": [
    {"id": "SERVICE_TOKEN_ID"},
    {"id": "SSL_KEY_ID"}
  ],
  "agent": {
    "monitoring": {
      "enabled": true,
      "use_output": "OUTPUT_ID",
      "logs": true,
      "metrics": true
    }
  },
  "fleet": {
    "hosts": ["http://localhost:8220"]
  }
}`

	var d model.PolicyData
	err := json.Unmarshal([]byte(policyPayload), &d)
	require.NoError(t, err)

	bulker := ftesting.NewMockBulk()
	pp, err := policy.NewParsedPolicy(t.Context(), bulker, model.Policy{
		PolicyID:    "policy1",
		RevisionIdx: 1,
		Data:        &d,
	})
	require.NoError(t, err)

	defaultOut := pp.Outputs["default"]
	remoteOut := pp.Outputs["OUTPUT_ID"]
	require.NotNil(t, defaultOut.Role)
	require.NotNil(t, remoteOut.Role)

	outputBulker := ftesting.NewMockBulk()
	bulker.On("CreateAndGetBulker", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(outputBulker, false, nil)

	defaultKey := bulk.APIKey{ID: "default-id", Key: "default-key"}
	remoteKey := bulk.APIKey{ID: "remote-id", Key: "remote-key"}
	agent := &model.Agent{
		ESDocument: model.ESDocument{Id: "agent1"},
		Outputs: map[string]*model.PolicyOutput{
			"default": {
				APIKey:          defaultKey.Agent(),
				APIKeyID:        defaultKey.ID,
				PermissionsHash: defaultOut.Role.Sha2,
				Type:            policy.OutputTypeElasticsearch,
			},
			"OUTPUT_ID": {
				APIKey:          remoteKey.Agent(),
				APIKeyID:        remoteKey.ID,
				PermissionsHash: remoteOut.Role.Sha2,
				Type:            policy.OutputTypeRemoteElasticsearch,
			},
		},
	}

	action, err := processPolicy(t.Context(), logger, bulker, agent, pp, nil)
	require.NoError(t, err)

	pc, err := action.Data.AsActionPolicyChange()
	require.NoError(t, err)

	assert.NotContains(t, pc.Policy.SecretPaths, "outputs.OUTPUT_ID.service_token")
	assert.Contains(t, pc.Policy.SecretPaths, "outputs.OUTPUT_ID.ssl.key")

	remotePolicy, ok := pc.Policy.Outputs["OUTPUT_ID"].(map[string]any)
	require.True(t, ok)
	_, hasServiceToken := remotePolicy["service_token"]
	assert.False(t, hasServiceToken, "service_token should be deleted by Prepare before delivery to agents")
	assert.Equal(t, policy.OutputTypeElasticsearch, remotePolicy["type"])
}
