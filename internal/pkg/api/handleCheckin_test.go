// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"compress/flate"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
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
			mBulk := ftesting.NewMockBulk()
			noUpgradeDetailsMockCheck(t, mBulk)
			return mBulk
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
			noUpgradeDetailsMockCheck(t, mBulk)
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
			mBulk := ftesting.NewMockBulk()
			noUpgradeDetailsMockCheck(t, mBulk)
			return mBulk
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
			mBulk := ftesting.NewMockBulk()
			noUpgradeDetailsMockCheck(t, mBulk)
			return mBulk
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
			mBulk := ftesting.NewMockBulk()
			noUpgradeDetailsMockCheck(t, mBulk)
			return mBulk
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
			upgradeDetailsMockCheck(t, mBulk)
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
			upgradeDetailsMockCheck(t, mBulk)
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
				upgradeDetailsMockCheck(t, mBulk)
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
				upgradeDetailsMockCheck(t, mBulk)
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
				upgradeDetailsMockCheck(t, mBulk)
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
				mBulk := ftesting.NewMockBulk()
				noUpgradeDetailsMockCheck(t, mBulk)
				return mBulk
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
				mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.MatchedBy(func(p []byte) bool {
					doc := struct {
						Doc map[string]interface{} `json:"doc"`
					}{}
					if err := json.Unmarshal(p, &doc); err != nil {
						t.Logf("bulk match unmarshal error: %v", err)
						return false
					}
					_, upgradeDetails := doc.Doc[dl.FieldUpgradeDetails]
					upgradeAttempts, ok := doc.Doc[dl.FieldUpgradeAttempts]
					return upgradeDetails && ok && upgradeAttempts == nil && doc.Doc[dl.FieldUpgradedAt] != ""
				}), mock.Anything, mock.Anything).Return(nil)
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

			bc := checkin.NewBulk(mBulk)
			ct := &CheckinT{
				cache:  mCache,
				bc:     bc,
				bulker: mBulk,
			}

			var err error
			opts := make([]checkin.Option, 0, 3)
			opts, err = ct.processUpgradeDetails(context.Background(), tc.agent, tc.details, opts)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
			}

			err = bc.CheckIn(context.Background(), tc.agent.Id, opts...)
			if err != nil {
				require.NoError(t, err)
			}

			mBulk.AssertExpectations(t)
			mCache.AssertExpectations(t)
		})
	}
}

func noUpgradeDetailsMockCheck(t *testing.T, mBulk *ftesting.MockBulk) {
	mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.MatchedBy(func(p []byte) bool {
		doc := struct {
			Doc map[string]interface{} `json:"doc"`
		}{}
		if err := json.Unmarshal(p, &doc); err != nil {
			t.Logf("bulk match unmarshal error: %v", err)
			return false
		}
		_, noUpgradeDetails := doc.Doc[dl.FieldUpgradeDetails]
		_, noUpgradeStartedAt := doc.Doc[dl.FieldUpgradeStartedAt]
		_, noUpgradeStatus := doc.Doc[dl.FieldUpgradeStatus]
		return !noUpgradeDetails && !noUpgradeStartedAt && !noUpgradeStatus && doc.Doc[dl.FieldUpgradedAt] != ""
	}), mock.Anything, mock.Anything).Return(nil)
}

func upgradeDetailsMockCheck(t *testing.T, mBulk *ftesting.MockBulk) {
	mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.MatchedBy(func(p []byte) bool {
		doc := struct {
			Doc map[string]interface{} `json:"doc"`
		}{}
		if err := json.Unmarshal(p, &doc); err != nil {
			t.Logf("bulk match unmarshal error: %v", err)
			return false
		}
		_, upgradeDetails := doc.Doc[dl.FieldUpgradeDetails]
		return upgradeDetails && doc.Doc[dl.FieldUpgradedAt] != ""
	}), mock.Anything, mock.Anything).Return(nil)
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
				Components: []model.ComponentsItems{{
					Status: "DEGRADED",
					Units: []model.UnitsItems{{
						Status: "DEGRADED", Type: "input",
					}},
				}},
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
				Components: []model.ComponentsItems{{
					Status: "HEALTHY",
					Units: []model.UnitsItems{{
						Status: "HEALTHY", Type: "input",
					}},
				}},
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

func TestValidateCheckinRequest(t *testing.T) {
	verCon := mustBuildConstraints("8.0.0")

	tests := []struct {
		name        string
		req         *http.Request
		cfg         *config.Server
		currentMeta json.RawMessage
		expErr      error
		expValid    validatedCheckin
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
				rawMeta: []byte(`{"elastic": {"agent": {"id": "testid", "fips": true}}}`),
			},
		},
		{
			name: "local metadata matches",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"status": "online", "message": "test message", "local_metadata": {"elastic": {"agent": {"id": "testid", "fips": true}}}}`)),
			},
			expErr:      nil,
			currentMeta: json.RawMessage(`{"elastic": {"agent": {"id": "testid", "fips": true}}}`),
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{
				rawMeta: nil, // no need to update
			},
		},
		{
			name: "local metadata different JSON formatting",
			req: &http.Request{
				// JSON with specific key ordering
				Body: io.NopCloser(strings.NewReader(`{"status": "online", "message": "test message", "local_metadata": {"elastic": {"agent": {"id": "testid", "version": "8.0.0"}}, "host": {"hostname": "test-host"}}}`)),
			},
			expErr: nil,
			// Same content but different key ordering in JSON - when unmarshaled and compared
			// with reflect.DeepEqual they should be equal, but raw bytes are different
			currentMeta: json.RawMessage(`{"host":{"hostname":"test-host"},"elastic":{"agent":{"version":"8.0.0","id":"testid"}}}`),
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{
				rawMeta: nil, // should recognize as same content despite different formatting
			},
		},
		{
			name: "local metadata is empty string and agent has nil",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"status": "online", "message": "test message", "local_metadata": ""}`)),
			},
			expErr:      nil,
			currentMeta: nil,
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{
				// don't update metadata
				rawMeta: nil,
			},
		},
		{
			name: "local metadata is empty string and agent has different value",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"status": "online", "message": "test message", "local_metadata": ""}`)),
			},
			expErr:      nil,
			currentMeta: json.RawMessage(`{"host": {"hostname": "test-host"}}`),
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{
				// don't update metadata
				rawMeta: nil,
			},
		},
		{
			name: "local metadata is null and agent has nil",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"status": "online", "message": "test message", "local_metadata": null}`)),
			},
			expErr:      nil,
			currentMeta: nil,
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{
				// don't update metadata
				rawMeta: nil,
			},
		},
		{
			name: "local metadata is null and agent has existing metadata",
			req: &http.Request{
				Body: io.NopCloser(strings.NewReader(`{"status": "online", "message": "test message", "local_metadata": null}`)),
			},
			expErr:      nil,
			currentMeta: json.RawMessage(`{"host": {"hostname": "test-host"}}`),
			cfg: &config.Server{
				Limits: config.ServerLimits{
					CheckinLimit: config.Limit{
						MaxBody: 0,
					},
				},
			},
			expValid: validatedCheckin{
				// don't update metadata
				rawMeta: nil,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkin, err := NewCheckinT(verCon, tc.cfg, nil, nil, nil, nil, nil, nil)
			assert.NoError(t, err)
			wr := httptest.NewRecorder()
			logger := testlog.SetLogger(t)
			valid, err := checkin.validateRequest(logger, wr, tc.req, time.Time{}, &model.Agent{LocalMetadata: tc.currentMeta})
			if tc.expErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, tc.expValid.rawMeta, valid.rawMeta)
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
	esd := model.ESDocument{Id: "doc-ID"}
	policyID := "policy-id"
	revIDX2 := int64(2)
	tests := []struct {
		name          string
		agent         *model.Agent
		req           *CheckinRequest
		policyID      string
		revIdx        int64
		bulk          func() *ftesting.MockBulk
		ignoreCheckin bool
	}{{
		name: "request has no policy details",
		agent: &model.Agent{
			ESDocument:        esd,
			PolicyID:          policyID,
			PolicyRevisionIdx: 1,
			Outputs: map[string]*model.PolicyOutput{
				"default": &model.PolicyOutput{
					APIKey: "123",
				},
			},
		},
		req:      &CheckinRequest{},
		policyID: policyID,
		revIdx:   1,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			noPolicyDetailsMockCheck(t, mBulk)
			return mBulk
		},
	}, {
		name: "policy reassign detected",
		agent: &model.Agent{
			ESDocument:        esd,
			PolicyID:          "new-policy-id",
			AgentPolicyID:     policyID,
			PolicyRevisionIdx: 2,
			Outputs: map[string]*model.PolicyOutput{
				"default": &model.PolicyOutput{
					APIKey: "123",
				},
			},
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		policyID: policyID,
		revIdx:   0,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			policyDetailsMockCheck(t, mBulk, policyID, revIDX2)
			return mBulk
		},
	}, {
		name: "no outputs",
		agent: &model.Agent{
			ESDocument:        esd,
			PolicyID:          policyID,
			AgentPolicyID:     policyID,
			PolicyRevisionIdx: 2,
		},
		req:      &CheckinRequest{},
		policyID: policyID,
		revIdx:   0,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			noPolicyDetailsMockCheck(t, mBulk)
			return mBulk
		},
	}, {
		name: "missing output APIKey",
		agent: &model.Agent{
			ESDocument:        esd,
			PolicyID:          policyID,
			AgentPolicyID:     policyID,
			PolicyRevisionIdx: 2,
			Outputs: map[string]*model.PolicyOutput{
				"default": &model.PolicyOutput{
					APIKey: "123",
				},
				"remote": &model.PolicyOutput{},
			},
		},
		req:      &CheckinRequest{},
		policyID: policyID,
		revIdx:   0,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			noPolicyDetailsMockCheck(t, mBulk)
			return mBulk
		},
	}, {
		name: "revision updated",
		agent: &model.Agent{
			ESDocument:        esd,
			PolicyID:          policyID,
			AgentPolicyID:     policyID,
			PolicyRevisionIdx: 1,
			Outputs: map[string]*model.PolicyOutput{
				"default": &model.PolicyOutput{
					APIKey: "123",
				},
			},
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		policyID: policyID,
		revIdx:   revIDX2,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			policyDetailsMockCheck(t, mBulk, policyID, revIDX2)
			return mBulk
		},
	}, {
		name: "agent does not have agent_policy_id present",
		agent: &model.Agent{
			ESDocument:        esd,
			PolicyID:          policyID,
			PolicyRevisionIdx: 2,
			Outputs: map[string]*model.PolicyOutput{
				"default": &model.PolicyOutput{
					APIKey: "123",
				},
			},
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		policyID: policyID,
		revIdx:   revIDX2,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			policyDetailsMockCheck(t, mBulk, policyID, revIDX2)
			return mBulk
		},
	}, {
		name: "details present with no changes for agent doc",
		agent: &model.Agent{
			ESDocument:        esd,
			AgentPolicyID:     policyID,
			PolicyID:          policyID,
			PolicyRevisionIdx: revIDX2,
			Outputs: map[string]*model.PolicyOutput{
				"default": &model.PolicyOutput{
					APIKey: "123",
				},
			},
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		policyID: policyID,
		revIdx:   revIDX2,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			policyDetailsMockCheck(t, mBulk, policyID, revIDX2)
			return mBulk
		},
	}, {
		name: "details present ignore checkin",
		agent: &model.Agent{
			ESDocument:        esd,
			AgentPolicyID:     policyID,
			PolicyID:          policyID,
			PolicyRevisionIdx: revIDX2,
			Outputs: map[string]*model.PolicyOutput{
				"default": &model.PolicyOutput{
					APIKey: "123",
				},
			},
		},
		req: &CheckinRequest{
			AgentPolicyId:     &policyID,
			PolicyRevisionIdx: &revIDX2,
		},
		policyID: policyID,
		revIdx:   revIDX2,
		bulk: func() *ftesting.MockBulk {
			mBulk := ftesting.NewMockBulk()
			noPolicyDetailsMockCheck(t, mBulk)
			return mBulk
		},
		ignoreCheckin: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)

			mBulk := tc.bulk()
			bc := checkin.NewBulk(mBulk)
			cfg := &config.Server{}
			if tc.ignoreCheckin {
				cfg.Features.IgnoreCheckinPolicyID = true
			}
			ct := &CheckinT{
				bc:     bc,
				bulker: mBulk,
				cfg:    cfg,
			}

			opts := make([]checkin.Option, 0, 2)
			opts, ePolicyID, eRevIdx, err := ct.processPolicyDetails(t.Context(), logger, tc.agent, tc.req, opts)
			require.NoError(t, err)
			assert.Equal(t, tc.policyID, ePolicyID)
			assert.Equal(t, tc.revIdx, eRevIdx)

			err = bc.CheckIn(t.Context(), tc.agent.Id, opts...)
			assert.NoError(t, err)

			mBulk.AssertExpectations(t)
		})
	}
}

func noPolicyDetailsMockCheck(t *testing.T, mBulk *ftesting.MockBulk) {
	mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.MatchedBy(func(p []byte) bool {
		doc := struct {
			Doc map[string]interface{} `json:"doc"`
		}{}
		if err := json.Unmarshal(p, &doc); err != nil {
			t.Logf("bulk match unmarshal error: %v", err)
			return false
		}
		_, noAgentPolicyID := doc.Doc[dl.FieldAgentPolicyID]
		_, noPolicyRevisionIdx := doc.Doc[dl.FieldPolicyRevisionIdx]
		return !noAgentPolicyID && !noPolicyRevisionIdx && doc.Doc[dl.FieldUpgradedAt] != ""
	}), mock.Anything, mock.Anything).Return(nil)
}

func policyDetailsMockCheck(t *testing.T, mBulk *ftesting.MockBulk, policyID string, revIdx int64) {
	mBulk.On("Update", mock.Anything, dl.FleetAgents, "doc-ID", mock.MatchedBy(func(p []byte) bool {
		doc := struct {
			Doc map[string]interface{} `json:"doc"`
		}{}
		if err := json.Unmarshal(p, &doc); err != nil {
			t.Logf("bulk match unmarshal error: %v", err)
			return false
		}
		oPolicyID, hasPolicy := doc.Doc[dl.FieldAgentPolicyID]
		if !hasPolicy {
			return false
		}
		oRevIdx, hasRevIdx := doc.Doc[dl.FieldPolicyRevisionIdx]
		if !hasRevIdx {
			return false
		}
		oRevIdxF, ok := oRevIdx.(float64)
		if !ok {
			return false
		}
		return oPolicyID == policyID && int64(oRevIdxF) == revIdx && doc.Doc[dl.FieldUpgradedAt] != ""
	}), mock.Anything, mock.Anything).Return(nil)
}
