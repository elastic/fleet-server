// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/gofrs/uuid/v5"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestFeatureFlag(t *testing.T) {
	cases := map[string]struct {
		FeatureFlagEnabled bool
		WantEnabled        bool
	}{
		"feature flag is explicitly disabled": {
			FeatureFlagEnabled: false,
			WantEnabled:        false,
		},
		"feature flag is explicitly enabled": {
			FeatureFlagEnabled: true,
			WantEnabled:        true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Server{
				Features: config.FeatureFlags{
					EnableOpAMP: tc.FeatureFlagEnabled,
				},
			}

			oa := OpAMPT{cfg: cfg}
			require.Equal(t, tc.WantEnabled, oa.Enabled())
		})
	}
}

func TestProtobufKVToRawMessage(t *testing.T) {
	input := []*protobufs.KeyValue{
		{
			Key: "string_key",
			Value: &protobufs.AnyValue{
				Value: &protobufs.AnyValue_StringValue{StringValue: "hello"},
			},
		},
		{
			Key: "int_key",
			Value: &protobufs.AnyValue{
				Value: &protobufs.AnyValue_IntValue{IntValue: 42},
			},
		},
		{
			Key: "double_key",
			Value: &protobufs.AnyValue{
				Value: &protobufs.AnyValue_DoubleValue{DoubleValue: 3.14},
			},
		},
		{
			Key: "bool_key",
			Value: &protobufs.AnyValue{
				Value: &protobufs.AnyValue_BoolValue{BoolValue: true},
			},
		},
		{
			Key: "bytes_key",
			Value: &protobufs.AnyValue{
				Value: &protobufs.AnyValue_BytesValue{BytesValue: []byte("bin")},
			},
		},
		{
			Key: "array_key",
			Value: &protobufs.AnyValue{
				Value: &protobufs.AnyValue_ArrayValue{ArrayValue: &protobufs.ArrayValue{
					Values: []*protobufs.AnyValue{
						{Value: &protobufs.AnyValue_StringValue{StringValue: "elem1"}},
						{Value: &protobufs.AnyValue_IntValue{IntValue: 2}},
					},
				}},
			},
		},
		{
			Key: "kvlist_key",
			Value: &protobufs.AnyValue{
				Value: &protobufs.AnyValue_KvlistValue{KvlistValue: &protobufs.KeyValueList{
					Values: []*protobufs.KeyValue{
						{
							Key: "nested_string_key",
							Value: &protobufs.AnyValue{
								Value: &protobufs.AnyValue_StringValue{StringValue: "nested"},
							},
						},
						{
							Key: "nested_int_key",
							Value: &protobufs.AnyValue{
								Value: &protobufs.AnyValue_IntValue{IntValue: 99},
							},
						},
					},
				}},
			},
		},
	}
	zlog := zerolog.New(io.Discard)
	raw, err := ProtobufKVToRawMessage(zlog, input)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "hello", got["string_key"])
	require.Equal(t, float64(42), got["int_key"])
	require.Equal(t, 3.14, got["double_key"])
	require.Equal(t, true, got["bool_key"])
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("bin")), got["bytes_key"])
	require.Equal(t, []any{"elem1", float64(2)}, got["array_key"])
	require.Equal(t, map[string]any{"nested_string_key": "nested", "nested_int_key": float64(99)}, got["kvlist_key"])
}

func TestEnrollAgentWithAgentToServerMessage(t *testing.T) {
	bulker := ftesting.NewMockBulk()

	enrollKey := model.EnrollmentAPIKey{ //nolint:gosec // fake api key used in test
		APIKeyID: "enroll-key-id",
		PolicyID: "policy-123",
		Active:   true,
	}
	enrollKeyBytes, err := json.Marshal(enrollKey) //nolint:gosec // fake api key used in test
	require.NoError(t, err)

	bulker.On("Search", mock.Anything, dl.FleetEnrollmentAPIKeys, mock.Anything, mock.Anything).
		Return(&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{{Source: enrollKeyBytes}},
			},
		}, nil)

	agentUID := uuid.Must(uuid.NewV7())
	var createdAgent model.Agent
	bulker.On("Create", mock.Anything, dl.FleetAgents, agentUID.String(), mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			body, ok := args.Get(3).([]byte)
			require.True(t, ok)
			require.NoError(t, json.Unmarshal(body, &createdAgent))
		}).
		Return("doc-id", nil)

	oa := &OpAMPT{bulk: bulker, enrollLimit: limit.NewLimiter(nil)}
	msg := &protobufs.AgentToServer{
		AgentDescription: &protobufs.AgentDescription{
			IdentifyingAttributes: []*protobufs.KeyValue{
				{
					Key: string(semconv.ServiceVersionKey),
					Value: &protobufs.AnyValue{
						Value: &protobufs.AnyValue_StringValue{StringValue: "1.2.3"},
					},
				},
				{
					Key: string(semconv.ServiceNameKey),
					Value: &protobufs.AnyValue{
						Value: &protobufs.AnyValue_StringValue{StringValue: "otel-collector"},
					},
				},
			},
			NonIdentifyingAttributes: []*protobufs.KeyValue{
				{
					Key: string(semconv.HostNameKey),
					Value: &protobufs.AnyValue{
						Value: &protobufs.AnyValue_StringValue{StringValue: "host-1"},
					},
				},
				{
					Key: string(semconv.OSTypeKey),
					Value: &protobufs.AnyValue{
						Value: &protobufs.AnyValue_StringValue{StringValue: "linux"},
					},
				},
			},
		},
	}

	apiKey := &apikey.APIKey{ID: "enroll-key-id"}
	zlog := zerolog.New(io.Discard)

	agent, err := oa.enrollAgent(t.Context(), zlog, agentUID, msg, apiKey)
	require.NoError(t, err)
	require.NotNil(t, agent)
	require.Equal(t, agentUID.String(), agent.Id)
	require.Equal(t, "policy-123", agent.PolicyID)
	require.Equal(t, "1.2.3", agent.Agent.Version)
	require.Equal(t, "otel-collector", agent.Agent.Type)
	require.Equal(t, []string{"otel-collector"}, agent.Tags)

	var meta localMetadata
	require.NoError(t, json.Unmarshal(agent.LocalMetadata, &meta))
	require.Equal(t, "host-1", meta.Host.Hostname)
	require.Equal(t, "linux", meta.Os.Platform)

	require.Equal(t, agent.Id, createdAgent.Agent.ID)
	require.Equal(t, agent.PolicyID, createdAgent.PolicyID)
	bulker.AssertExpectations(t)
}

func TestEnrollAgentRateLimiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bulker := ftesting.NewMockBulk()
		enrollKey := model.EnrollmentAPIKey{ //nolint:gosec // fake api key used in test
			APIKeyID: "enroll-key-id",
			PolicyID: "policy-123",
			Active:   true,
		}
		enrollKeyBytes, err := json.Marshal(enrollKey) //nolint:gosec // fake api key used in test
		require.NoError(t, err)

		bulker.On("Search", mock.Anything, dl.FleetEnrollmentAPIKeys, mock.Anything, mock.Anything).
			Return(&es.ResultT{
				HitsT: es.HitsT{
					Hits: []es.HitT{{Source: enrollKeyBytes}},
				},
			}, nil)

		agentUID := uuid.Must(uuid.NewV7())
		oa := &OpAMPT{bulk: bulker, enrollLimit: limit.NewLimiter(&config.Limit{Max: 1})}

		ch := make(chan struct{})
		bulker.On("Create", mock.Anything, dl.FleetAgents, agentUID.String(), mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				ch <- struct{}{}
			}).
			Return("doc-id", nil)

		apiKey := &apikey.APIKey{ID: "enroll-key-id"}
		zlog := zerolog.New(io.Discard)

		go func() {
			_, err := oa.enrollAgent(t.Context(), zlog, agentUID, &protobufs.AgentToServer{}, apiKey)
			require.NoError(t, err, "expected one enrollment to succeed")
		}()

		synctest.Wait()

		_, err = oa.enrollAgent(t.Context(), zlog, agentUID, &protobufs.AgentToServer{}, apiKey)
		require.Error(t, err, "expected max limit to be reached")

		<-ch
		synctest.Wait()
	})
}

// TestEnrollAgentGeneratesNewUIDWhenFlagSet verifies enrollAgent generates a
// fresh UUID when the AgentToServer message sets the RequestInstanceUid flag,
// ignoring the incoming uid argument.
func TestEnrollAgentGeneratesNewUIDWhenFlagSet(t *testing.T) {
	bulker := ftesting.NewMockBulk()

	enrollKey := model.EnrollmentAPIKey{ //nolint:gosec // fake api key used in test
		APIKeyID: "enroll-key-id",
		PolicyID: "policy-123",
		Active:   true,
	}
	enrollKeyBytes, err := json.Marshal(enrollKey) //nolint:gosec // fake api key used in test
	require.NoError(t, err)

	bulker.On("Search", mock.Anything, dl.FleetEnrollmentAPIKeys, mock.Anything, mock.Anything).
		Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{Source: enrollKeyBytes}}}}, nil)

	var createdID string
	bulker.On("Create", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			id, ok := args.Get(2).(string)
			require.True(t, ok)
			createdID = id
		}).
		Return("doc-id", nil)

	oa := &OpAMPT{bulk: bulker, enrollLimit: limit.NewLimiter(nil)}
	incomingUID := uuid.Must(uuid.NewV7())
	msg := &protobufs.AgentToServer{
		Flags: uint64(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid),
	}

	apiKey := &apikey.APIKey{ID: "enroll-key-id"}
	zlog := zerolog.New(io.Discard)

	agent, err := oa.enrollAgent(t.Context(), zlog, incomingUID, msg, apiKey)
	require.NoError(t, err)
	require.NotEmpty(t, agent.Id)
	require.NotEqual(t, incomingUID.String(), agent.Id, "agent should be enrolled under a new UID, not the incoming one")
	require.Equal(t, agent.Id, createdID)
}

func TestEnrollAgentTags(t *testing.T) {
	cases := []struct {
		name         string
		tagsValue    string
		wantTags     []string
		otherNIAKeys []string
	}{
		{
			name:         "no tags attribute",
			tagsValue:    "",
			wantTags:     []string{"otel-collector"},
			otherNIAKeys: []string{string(semconv.HostNameKey)},
		},
		{
			name:         "single tag",
			tagsValue:    "dev",
			wantTags:     []string{"otel-collector", "dev"},
			otherNIAKeys: []string{string(semconv.HostNameKey)},
		},
		{
			name:         "multiple tags",
			tagsValue:    "dev,west,us-west-1a",
			wantTags:     []string{"otel-collector", "dev", "west", "us-west-1a"},
			otherNIAKeys: []string{string(semconv.HostNameKey)},
		},
		{
			name:         "tags with spaces",
			tagsValue:    " dev , west , us-west-1a ",
			wantTags:     []string{"otel-collector", "dev", "west", "us-west-1a"},
			otherNIAKeys: []string{string(semconv.HostNameKey)},
		},
		{
			name:         "duplicate of agent type is removed",
			tagsValue:    "otel-collector,dev",
			wantTags:     []string{"otel-collector", "dev"},
			otherNIAKeys: []string{string(semconv.HostNameKey)},
		},
		{
			name:         "duplicate tags within list are removed",
			tagsValue:    "dev,west,dev",
			wantTags:     []string{"otel-collector", "dev", "west"},
			otherNIAKeys: []string{string(semconv.HostNameKey)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bulker := ftesting.NewMockBulk()
			enrollKey := model.EnrollmentAPIKey{ //nolint:gosec // test data, not real credentials
				APIKeyID: "enroll-key-id",
				PolicyID: "policy-123",
				Active:   true,
			}
			enrollKeyBytes, err := json.Marshal(enrollKey) //nolint:gosec // test data, not real credentials
			require.NoError(t, err)
			bulker.On("Search", mock.Anything, dl.FleetEnrollmentAPIKeys, mock.Anything, mock.Anything).
				Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{Source: enrollKeyBytes}}}}, nil)
			agentUID := uuid.Must(uuid.NewV7())
			bulker.On("Create", mock.Anything, dl.FleetAgents, agentUID.String(), mock.Anything, mock.Anything).
				Return("doc-id", nil)

			nia := []*protobufs.KeyValue{
				{
					Key:   string(semconv.HostNameKey),
					Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "host-1"}},
				},
			}
			if tc.tagsValue != "" {
				nia = append(nia, &protobufs.KeyValue{
					Key:   "tags",
					Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: tc.tagsValue}},
				})
			}

			msg := &protobufs.AgentToServer{
				AgentDescription: &protobufs.AgentDescription{
					IdentifyingAttributes: []*protobufs.KeyValue{
						{
							Key:   string(semconv.ServiceNameKey),
							Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "otel-collector"}},
						},
					},
					NonIdentifyingAttributes: nia,
				},
			}

			oa := &OpAMPT{bulk: bulker, enrollLimit: limit.NewLimiter(nil)}
			zlog := zerolog.New(io.Discard)
			agent, err := oa.enrollAgent(t.Context(), zlog, agentUID, msg, &apikey.APIKey{ID: "enroll-key-id"})
			require.NoError(t, err)
			require.Equal(t, tc.wantTags, agent.Tags)

			// tags must not appear in stored NonIdentifyingAttributes
			var niMap map[string]any
			require.NoError(t, json.Unmarshal(agent.NonIdentifyingAttributes, &niMap))
			require.NotContains(t, niMap, "tags")
			for _, k := range tc.otherNIAKeys {
				require.Contains(t, niMap, k, "expected NIA key %q to be present", k)
			}
		})
	}
}

func TestUpdateAgentWithAgentToServerMessage(t *testing.T) {
	t.Run("normal checkin", func(t *testing.T) {
		checker := &mockCheckin{}
		oa := &OpAMPT{bc: checker}

		agent := &model.Agent{ESDocument: model.ESDocument{Id: "agent-123"}}

		msg := &protobufs.AgentToServer{
			SequenceNum: 7,
			Capabilities: uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig),
			Health: &protobufs.ComponentHealth{
				Healthy:   true,
				Status:    "StatusRecoverableError",
				LastError: "boom",
			},
			EffectiveConfig: &protobufs.EffectiveConfig{
				ConfigMap: &protobufs.AgentConfigMap{
					ConfigMap: map[string]*protobufs.AgentConfigFile{
						"": {
							Body:        []byte("password: 12345\nnum: 2\n"),
							ContentType: "text/yaml",
						},
					},
				},
			},
		}

		zlog := zerolog.New(io.Discard)
		require.NoError(t, oa.updateAgent(zlog, agent, msg))
		require.Equal(t, "agent-123", checker.id)

		pending := pendingFromOptions(t, checker.opts)
		require.Equal(t, string(CheckinRequestStatusDegraded), getUnexportedField(pending, "status").String())
		require.Equal(t, "boom", getUnexportedField(pending, "message").String())
		require.Equal(t, uint64(7), getUnexportedField(pending, "sequenceNum").Uint())

		extra := getUnexportedField(pending, "extra")
		require.False(t, extra.IsNil())
		extraVal := extra.Elem()

		capabilitiesVal := getUnexportedField(extraVal, "capabilities")
		capabilities, ok := capabilitiesVal.Interface().([]string)
		require.True(t, ok)
		require.ElementsMatch(t, []string{"ReportsHealth", "AcceptsRemoteConfig"}, capabilities)

		healthBytes := getUnexportedField(extraVal, "health").Bytes()
		var health protobufs.ComponentHealth
		require.NoError(t, json.Unmarshal(healthBytes, &health))
		require.Equal(t, "boom", health.LastError)
		require.Equal(t, "StatusRecoverableError", health.Status)

		configBytes := getUnexportedField(extraVal, "effectiveConfig").Bytes()
		var config map[string]any
		require.NoError(t, json.Unmarshal(configBytes, &config))
		require.Equal(t, "[REDACTED]", config["password"])
		require.Equal(t, float64(2), config["num"])
	})

	t.Run("checkin clears audit_unenroll attributes", func(t *testing.T) {
		checker := &mockCheckin{}
		oa := &OpAMPT{bc: checker}

		agent := &model.Agent{
			ESDocument:            model.ESDocument{Id: "agent-123"},
			AuditUnenrolledReason: reenrolled,
			AuditUnenrolledTime:   time.Now().UTC().Format(time.RFC3339),
		}

		msg := &protobufs.AgentToServer{
			SequenceNum:  3,
			Capabilities: uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth),
			Health: &protobufs.ComponentHealth{
				Healthy: true,
			},
		}

		zlog := zerolog.New(io.Discard)
		require.NoError(t, oa.updateAgent(zlog, agent, msg))
		require.Equal(t, "agent-123", checker.id)

		pending := pendingFromOptions(t, checker.opts)
		require.Equal(t, string(CheckinRequestStatusOnline), getUnexportedField(pending, "status").String())

		extra := getUnexportedField(pending, "extra")
		require.False(t, extra.IsNil())
		extraVal := extra.Elem()

		capabilitiesVal := getUnexportedField(extraVal, "capabilities")
		capabilities, ok := capabilitiesVal.Interface().([]string)
		require.True(t, ok)
		require.ElementsMatch(t, []string{"ReportsHealth"}, capabilities)

		deleteAuditVal := getUnexportedField(extraVal, "deleteAudit")
		deleteAudit, ok := deleteAuditVal.Interface().(bool)
		require.True(t, ok)
		require.True(t, deleteAudit)
	})
}

func TestHandleMessageAgentDisconnect(t *testing.T) {
	cases := []struct {
		name      string
		getBulker func(t *testing.T) *ftesting.MockBulk
		wantError bool
	}{
		{
			name: "enrolled agent sets status to offline",
			getBulker: func(t *testing.T) *ftesting.MockBulk {
				t.Helper()
				bulker := ftesting.NewMockBulk()
				agent := model.Agent{LastCheckinStatus: string(CheckinRequestStatusOnline)}
				agentBytes, err := json.Marshal(agent)
				require.NoError(t, err)
				bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{ID: "agent-123", Source: agentBytes}}}}, nil)
				return bulker
			},
			wantError: false,
		},
		{
			name: "unenrolled agent returns error",
			getBulker: func(_ *testing.T) *ftesting.MockBulk {
				bulker := ftesting.NewMockBulk()
				bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{}}}, nil)
				return bulker
			},
			wantError: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bulker := tc.getBulker(t)
			checker := &mockCheckin{}
			oa := &OpAMPT{bulk: bulker, bc: checker, enrollLimit: limit.NewLimiter(nil)}

			agentUID := uuid.Must(uuid.NewV7())
			zlog := zerolog.New(io.Discard)
			apiKey := &apikey.APIKey{ID: "test-key"}

			handler := oa.handleMessage(zlog, apiKey)
			msg := &protobufs.AgentToServer{
				InstanceUid:     agentUID.Bytes(),
				AgentDisconnect: &protobufs.AgentDisconnect{},
			}

			resp := handler(t.Context(), nil, msg)
			require.Equal(t, agentUID.Bytes(), resp.InstanceUid)

			if tc.wantError {
				require.NotNil(t, resp.ErrorResponse)
				require.Equal(t, protobufs.ServerErrorResponseType_ServerErrorResponseType_BadRequest, resp.ErrorResponse.Type)
				require.Empty(t, checker.id, "CheckIn should not be called for unenrolled agent")
			} else {
				require.Nil(t, resp.ErrorResponse)
				require.Equal(t, uint64(0), resp.Capabilities)
				require.Equal(t, agentUID.String(), checker.id)

				pending := pendingFromOptions(t, checker.opts)
				require.Equal(t, string(CheckinRequestStatusDisconnected), getUnexportedField(pending, "status").String())
			}
		})
	}
}

func mockBulkerOpAMPNewEnrollment(t *testing.T, apiKeyID string) *ftesting.MockBulk {
	t.Helper()
	bulker := ftesting.NewMockBulk()
	bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
		Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{}}}, nil)
	enrollKey := model.EnrollmentAPIKey{
		APIKeyID: apiKeyID,
		PolicyID: "policy-123",
		Active:   true,
	}
	enrollKeyBytes, err := json.Marshal(enrollKey) //nolint:gosec // fake api key used in test
	require.NoError(t, err)
	bulker.On("Search", mock.Anything, dl.FleetEnrollmentAPIKeys, mock.Anything, mock.Anything).
		Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{Source: enrollKeyBytes}}}}, nil)
	bulker.On("Create", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything, mock.Anything).
		Return("doc-id", nil)
	return bulker
}

func mockBulkerOpAMPExistingAgent(t *testing.T, lastCheckinStatus string) *ftesting.MockBulk {
	t.Helper()
	bulker := ftesting.NewMockBulk()
	agent := model.Agent{LastCheckinStatus: lastCheckinStatus}
	agentBytes, err := json.Marshal(agent)
	require.NoError(t, err)
	bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
		Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{ID: "agent-123", Source: agentBytes}}}}, nil)
	return bulker
}

func TestHandleMessageCapabilities(t *testing.T) {
	const testAPIKeyID = "test-key"

	cases := []struct {
		name      string
		getBulker func(t *testing.T) *ftesting.MockBulk
		wantCaps  uint64
	}{
		{
			name:      "new enrollment sends capabilities",
			getBulker: func(t *testing.T) *ftesting.MockBulk { return mockBulkerOpAMPNewEnrollment(t, testAPIKeyID) },
			wantCaps:  serverCapabilities,
		},
		{
			name:      "offline agent sends capabilities",
			getBulker: func(t *testing.T) *ftesting.MockBulk { return mockBulkerOpAMPExistingAgent(t, "offline") },
			wantCaps:  serverCapabilities,
		},
		{
			name: "disconnected agent sends capabilities",
			getBulker: func(t *testing.T) *ftesting.MockBulk {
				return mockBulkerOpAMPExistingAgent(t, string(CheckinRequestStatusDisconnected))
			},
			wantCaps: serverCapabilities,
		},
		{
			name: "online agent does not send capabilities",
			getBulker: func(t *testing.T) *ftesting.MockBulk {
				return mockBulkerOpAMPExistingAgent(t, string(CheckinRequestStatusOnline))
			},
			wantCaps: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bulker := tc.getBulker(t)
			checker := &mockCheckin{}
			oa := &OpAMPT{bulk: bulker, bc: checker, enrollLimit: limit.NewLimiter(nil)}

			agentUID := uuid.Must(uuid.NewV7())
			zlog := zerolog.New(io.Discard)
			apiKey := &apikey.APIKey{ID: testAPIKeyID}

			handler := oa.handleMessage(zlog, apiKey)
			msg := &protobufs.AgentToServer{
				InstanceUid: agentUID.Bytes(),
			}

			resp := handler(t.Context(), nil, msg)

			require.Nil(t, resp.ErrorResponse)
			require.Equal(t, tc.wantCaps, resp.Capabilities)
		})
	}
}

func TestHandleMessageRequestInstanceUid(t *testing.T) {
	const testAPIKeyID = "test-key"

	cases := []struct {
		name                    string
		flags                   uint64
		getBulker               func(t *testing.T, enrolledDocID *string) *ftesting.MockBulk
		wantAgentIdentification bool
	}{
		{
			name:  "RequestInstanceUid flag forces new enrollment with a fresh UID",
			flags: uint64(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid),
			getBulker: func(t *testing.T, enrolledDocID *string) *ftesting.MockBulk {
				t.Helper()
				bulker := ftesting.NewMockBulk()
				bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{}}}, nil)
				enrollKey := model.EnrollmentAPIKey{
					APIKeyID: testAPIKeyID,
					PolicyID: "policy-123",
					Active:   true,
				}
				enrollKeyBytes, err := json.Marshal(enrollKey) //nolint:gosec // fake api key used in test
				require.NoError(t, err)
				bulker.On("Search", mock.Anything, dl.FleetEnrollmentAPIKeys, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{Source: enrollKeyBytes}}}}, nil)
				bulker.On("Create", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						id, ok := args.Get(2).(string)
						require.True(t, ok)
						*enrolledDocID = id
					}).
					Return("doc-id", nil)
				return bulker
			},
			wantAgentIdentification: true,
		},
		{
			name:  "enrolled agent without flag does not get AgentIdentification",
			flags: 0,
			getBulker: func(t *testing.T, _ *string) *ftesting.MockBulk {
				t.Helper()
				return mockBulkerOpAMPExistingAgent(t, string(CheckinRequestStatusOnline))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var enrolledDocID string
			bulker := tc.getBulker(t, &enrolledDocID)
			checker := &mockCheckin{}
			oa := &OpAMPT{bulk: bulker, bc: checker, enrollLimit: limit.NewLimiter(nil)}

			agentUID := uuid.Must(uuid.NewV7())
			zlog := zerolog.New(io.Discard)
			apiKey := &apikey.APIKey{ID: testAPIKeyID}

			handler := oa.handleMessage(zlog, apiKey)
			msg := &protobufs.AgentToServer{
				InstanceUid: agentUID.Bytes(),
				Flags:       tc.flags,
			}

			resp := handler(t.Context(), nil, msg)
			require.Nil(t, resp.ErrorResponse)
			require.Equal(t, agentUID.Bytes(), resp.InstanceUid)

			if tc.wantAgentIdentification {
				require.NotNil(t, resp.AgentIdentification)
				newUID, err := uuid.FromBytes(resp.AgentIdentification.NewInstanceUid)
				require.NoError(t, err)
				require.NotEqual(t, agentUID, newUID, "new instance UID must differ from original")
				require.Equal(t, newUID.String(), enrolledDocID, "enrollment should use the new instance UID")
				require.Equal(t, newUID.String(), checker.id, "checkin should use the new instance UID")
			} else {
				require.Nil(t, resp.AgentIdentification)
			}
			require.NotEmpty(t, checker.id, "checkin should be called")
			bulker.AssertExpectations(t)
		})
	}
}

// TestUnenrollAgent verifies the body and options used when marking the old
// agent doc as reenrolled.
func TestUnenrollAgent(t *testing.T) {
	const oldID = "old-agent-id"

	bulker := ftesting.NewMockBulk()
	var capturedBody []byte
	bulker.On("Update", mock.Anything, dl.FleetAgents, oldID, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			body, ok := args.Get(3).([]byte)
			require.True(t, ok)
			capturedBody = body
		}).
		Return(nil)

	oa := &OpAMPT{bulk: bulker}
	zlog := zerolog.New(io.Discard)
	require.NoError(t, oa.unenrollAgent(t.Context(), zlog, oldID))

	var doc map[string]any
	require.NoError(t, json.Unmarshal(capturedBody, &doc))
	fields, ok := doc["doc"].(map[string]any)
	require.True(t, ok, "expected update body to wrap fields under \"doc\"")
	require.Equal(t, reenrolled, fields[dl.FieldAuditUnenrolledReason])
	require.NotEmpty(t, fields[dl.FieldAuditUnenrolledTime])
	require.NotEmpty(t, fields[dl.FieldUpdatedAt])

	bulker.AssertExpectations(t)
}

// TestHandleMessageReenrollOldDocBehavior covers when handleMessage marks the
// previous agent document as reenrolled. With the RequestInstanceUid flag set,
// the old doc is updated only when its existing audit_unenrolled_reason is
// neither "orphaned" nor "reenrolled".
func TestHandleMessageReenrollOldDocBehavior(t *testing.T) {
	const testAPIKeyID = "test-key"

	enrollKey := model.EnrollmentAPIKey{
		APIKeyID: testAPIKeyID,
		PolicyID: "policy-123",
		Active:   true,
	}
	enrollKeyBytes, err := json.Marshal(enrollKey) //nolint:gosec // fake api key used in test
	require.NoError(t, err)

	cases := []struct {
		name             string
		flags            uint64
		auditReason      string
		wantUpdateCalled bool
	}{
		{
			name:             "active enrolled agent with flag marks old doc",
			flags:            uint64(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid),
			auditReason:      "",
			wantUpdateCalled: true,
		},
		{
			name:             "orphaned enrolled agent with flag does not re-mark",
			flags:            uint64(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid),
			auditReason:      string(Orphaned),
			wantUpdateCalled: false,
		},
		{
			name:             "reenrolled enrolled agent with flag does not re-mark",
			flags:            uint64(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid),
			auditReason:      reenrolled,
			wantUpdateCalled: false,
		},
		{
			name:             "uninstall enrolled agent with flag marks old doc",
			flags:            uint64(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid),
			auditReason:      string(Uninstall),
			wantUpdateCalled: true,
		},
		{
			name:             "enrolled agent without flag does not mark old doc",
			flags:            0,
			auditReason:      "",
			wantUpdateCalled: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bulker := ftesting.NewMockBulk()
			agent := model.Agent{
				LastCheckinStatus:     string(CheckinRequestStatusOnline),
				AuditUnenrolledReason: tc.auditReason,
			}
			agentBytes, err := json.Marshal(agent)
			require.NoError(t, err)
			bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
				Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{ID: "agent-123", Source: agentBytes}}}}, nil)

			if tc.flags&uint64(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid) != 0 {
				bulker.On("Search", mock.Anything, dl.FleetEnrollmentAPIKeys, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{Source: enrollKeyBytes}}}}, nil)
				bulker.On("Create", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything, mock.Anything).
					Return("doc-id", nil)
			}

			var updatedID string
			if tc.wantUpdateCalled {
				bulker.On("Update", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything, mock.Anything).
					Run(func(args mock.Arguments) {
						id, ok := args.Get(2).(string)
						require.True(t, ok)
						updatedID = id
					}).
					Return(nil)
			}

			checker := &mockCheckin{}
			oa := &OpAMPT{bulk: bulker, bc: checker, enrollLimit: limit.NewLimiter(nil)}

			agentUID := uuid.Must(uuid.NewV7())
			zlog := zerolog.New(io.Discard)
			apiKey := &apikey.APIKey{ID: testAPIKeyID}

			handler := oa.handleMessage(zlog, apiKey)
			msg := &protobufs.AgentToServer{
				InstanceUid: agentUID.Bytes(),
				Flags:       tc.flags,
			}

			resp := handler(t.Context(), nil, msg)
			require.Nil(t, resp.ErrorResponse)

			if tc.wantUpdateCalled {
				require.Equal(t, agentUID.String(), updatedID, "Update should target the original instance UID (the old doc)")
			} else {
				bulker.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			}
			bulker.AssertExpectations(t)
		})
	}
}

type mockCheckin struct {
	id   string
	opts []checkin.Option
}

func (m *mockCheckin) CheckIn(id string, opts ...checkin.Option) error {
	m.id = id
	m.opts = opts
	return nil
}

func pendingFromOptions(t *testing.T, opts []checkin.Option) reflect.Value {
	t.Helper()
	require.NotEmpty(t, opts)

	_ = checkin.WithStatus("")
	argType := reflect.TypeFor[checkin.Option]().In(0)
	pendingPtr := reflect.New(argType.Elem())
	for _, opt := range opts {
		reflect.ValueOf(opt).Call([]reflect.Value{pendingPtr})
	}
	return pendingPtr.Elem()
}

func TestDecodeCapabilities(t *testing.T) {
	cases := []struct {
		name string
		caps uint64
		want []string
	}{
		{
			name: "zero returns empty",
			caps: 0,
			want: nil,
		},
		{
			name: "single capability",
			caps: uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth),
			want: []string{"ReportsHealth"},
		},
		{
			name: "multiple capabilities",
			caps: uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsOwnLogs),
			want: []string{"AcceptsRemoteConfig", "ReportsOwnLogs", "ReportsHealth"},
		},
		{
			name: "all capabilities",
			caps: uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsPackages) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsOwnTraces) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsOwnMetrics) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsOwnLogs) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsOpAMPConnectionSettings) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsOtherConnectionSettings) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRestartCommand) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHeartbeat) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsAvailableComponents) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsConnectionSettingsStatus),
			want: []string{
				"ReportsStatus",
				"AcceptsRemoteConfig",
				"ReportsEffectiveConfig",
				"AcceptsPackages",
				"ReportsPackageStatuses",
				"ReportsOwnTraces",
				"ReportsOwnMetrics",
				"ReportsOwnLogs",
				"AcceptsOpAMPConnectionSettings",
				"AcceptsOtherConnectionSettings",
				"AcceptsRestartCommand",
				"ReportsHealth",
				"ReportsRemoteConfig",
				"ReportsHeartbeat",
				"ReportsAvailableComponents",
				"ReportsConnectionSettingsStatus",
			},
		},
		{
			name: "unknown bits are ignored",
			caps: uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth) | (1 << 40),
			want: []string{"ReportsHealth"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeCapabilities(tc.caps)
			require.ElementsMatch(t, tc.want, got)
		})
	}
}

func getUnexportedField(v reflect.Value, name string) reflect.Value {
	field := v.FieldByName(name)
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}
