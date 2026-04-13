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

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &got))

	require.Equal(t, "hello", got["string_key"])
	require.Equal(t, float64(42), got["int_key"])
	require.Equal(t, 3.14, got["double_key"])
	require.Equal(t, true, got["bool_key"])
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("bin")), got["bytes_key"])
	require.Equal(t, []interface{}{"elem1", float64(2)}, got["array_key"])
	require.Equal(t, map[string]interface{}{"nested_string_key": "nested", "nested_int_key": float64(99)}, got["kvlist_key"])
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

	var createdAgent model.Agent
	bulker.On("Create", mock.Anything, dl.FleetAgents, "agent-123", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			body, ok := args.Get(3).([]byte)
			require.True(t, ok)
			require.NoError(t, json.Unmarshal(body, &createdAgent))
		}).
		Return("doc-id", nil)

	oa := &OpAMPT{bulk: bulker}
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

	agent, err := oa.enrollAgent(zlog, "agent-123", msg, apiKey)
	require.NoError(t, err)
	require.NotNil(t, agent)
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

func TestUpdateAgentWithAgentToServerMessage(t *testing.T) {
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
	var config map[string]interface{}
	require.NoError(t, json.Unmarshal(configBytes, &config))
	require.Equal(t, "[REDACTED]", config["password"])
	require.Equal(t, float64(2), config["num"])
}

func TestHandleMessageAgentDisconnect(t *testing.T) {
	//nolint:dupl // test cases
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
			oa := &OpAMPT{bulk: bulker, bc: checker}

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

func TestHandleMessageCapabilities(t *testing.T) {
	const testAPIKeyID = "test-key"

	//nolint:dupl // test cases
	cases := []struct {
		name      string
		getBulker func(t *testing.T) *ftesting.MockBulk
		wantCaps  uint64
	}{
		{
			name: "new enrollment sends capabilities",
			getBulker: func(t *testing.T) *ftesting.MockBulk {
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
					Return("doc-id", nil)
				return bulker
			},
			wantCaps: serverCapabilities,
		},
		{
			name: "offline agent sends capabilities",
			getBulker: func(t *testing.T) *ftesting.MockBulk {
				t.Helper()
				bulker := ftesting.NewMockBulk()
				agent := model.Agent{LastCheckinStatus: "offline"}
				agentBytes, err := json.Marshal(agent)
				require.NoError(t, err)
				bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{ID: "agent-123", Source: agentBytes}}}}, nil)
				return bulker
			},
			wantCaps: serverCapabilities,
		},
		{
			name: "disconnected agent sends capabilities",
			getBulker: func(t *testing.T) *ftesting.MockBulk {
				t.Helper()
				bulker := ftesting.NewMockBulk()
				agent := model.Agent{LastCheckinStatus: string(CheckinRequestStatusDisconnected)}
				agentBytes, err := json.Marshal(agent)
				require.NoError(t, err)
				bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{ID: "agent-123", Source: agentBytes}}}}, nil)
				return bulker
			},
			wantCaps: serverCapabilities,
		},
		{
			name: "online agent does not send capabilities",
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
			wantCaps: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bulker := tc.getBulker(t)
			checker := &mockCheckin{}
			oa := &OpAMPT{bulk: bulker, bc: checker}

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

	sampleOpt := checkin.WithStatus("")
	argType := reflect.TypeOf(sampleOpt).In(0)
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

func TestHasFullStatus(t *testing.T) {
	baseCaps := uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus)

	cases := []struct {
		name string
		msg  *protobufs.AgentToServer
		want bool
	}{
		{
			name: "capabilities unset",
			msg: &protobufs.AgentToServer{
				Capabilities:     0,
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{},
			},
			want: false,
		},
		{
			name: "base fields only, no conditional capabilities",
			msg: &protobufs.AgentToServer{
				Capabilities:     baseCaps,
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{},
			},
			want: true,
		},
		{
			name: "missing AgentDescription",
			msg: &protobufs.AgentToServer{
				Capabilities: baseCaps,
				Health:       &protobufs.ComponentHealth{},
			},
			want: false,
		},
		{
			name: "missing Health",
			msg: &protobufs.AgentToServer{
				Capabilities:     baseCaps,
				AgentDescription: &protobufs.AgentDescription{},
			},
			want: false,
		},
		{
			name: "ReportsEffectiveConfig capability without EffectiveConfig",
			msg: &protobufs.AgentToServer{
				Capabilities:     baseCaps | uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig),
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{},
			},
			want: false,
		},
		{
			name: "ReportsEffectiveConfig capability with EffectiveConfig",
			msg: &protobufs.AgentToServer{
				Capabilities:     baseCaps | uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig),
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{},
				EffectiveConfig:  &protobufs.EffectiveConfig{},
			},
			want: true,
		},
		{
			name: "ReportsRemoteConfig capability without RemoteConfigStatus",
			msg: &protobufs.AgentToServer{
				Capabilities:     baseCaps | uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig),
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{},
			},
			want: false,
		},
		{
			name: "ReportsPackageStatuses capability without PackageStatuses",
			msg: &protobufs.AgentToServer{
				Capabilities:     baseCaps | uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsPackageStatuses),
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{},
			},
			want: false,
		},
		{
			name: "ReportsAvailableComponents capability without AvailableComponents",
			msg: &protobufs.AgentToServer{
				Capabilities:     baseCaps | uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsAvailableComponents),
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{},
			},
			want: false,
		},
		{
			name: "ReportsConnectionSettingsStatus capability without ConnectionSettingsStatus",
			msg: &protobufs.AgentToServer{
				Capabilities:     baseCaps | uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsConnectionSettingsStatus),
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{},
			},
			want: false,
		},
		{
			name: "multiple capabilities all fields present",
			msg: &protobufs.AgentToServer{
				Capabilities: baseCaps |
					uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig) |
					uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig),
				AgentDescription:   &protobufs.AgentDescription{},
				Health:             &protobufs.ComponentHealth{},
				EffectiveConfig:    &protobufs.EffectiveConfig{},
				RemoteConfigStatus: &protobufs.RemoteConfigStatus{},
			},
			want: true,
		},
		{
			name: "all fields missing",
			msg:  &protobufs.AgentToServer{},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, hasFullStatus(tc.msg))
		})
	}
}

func TestShouldRequestFullState(t *testing.T) {
	baseCaps := uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus)

	fullStatusMsg := func(seqNum uint64) *protobufs.AgentToServer {
		return &protobufs.AgentToServer{
			SequenceNum:      seqNum,
			Capabilities:     baseCaps,
			AgentDescription: &protobufs.AgentDescription{},
			Health:           &protobufs.ComponentHealth{},
		}
	}

	cases := []struct {
		name          string
		agent         *model.Agent
		msg           *protobufs.AgentToServer
		newlyEnrolled bool
		want          bool
	}{
		{
			name:          "sequence gap - missed message",
			agent:         &model.Agent{SequenceNum: 5, LastCheckinStatus: "online"},
			msg:           &protobufs.AgentToServer{SequenceNum: 7, Capabilities: baseCaps},
			newlyEnrolled: false,
			want:          true,
		},
		{
			name:          "sequence gap - out of order",
			agent:         &model.Agent{SequenceNum: 5, LastCheckinStatus: "online"},
			msg:           &protobufs.AgentToServer{SequenceNum: 3, Capabilities: baseCaps},
			newlyEnrolled: false,
			want:          true,
		},
		{
			name:          "no sequence gap - sequential",
			agent:         &model.Agent{SequenceNum: 5, LastCheckinStatus: "online"},
			msg:           fullStatusMsg(6),
			newlyEnrolled: false,
			want:          false,
		},
		{
			name:          "new enrollment without full status",
			agent:         &model.Agent{},
			msg:           &protobufs.AgentToServer{SequenceNum: 1, Capabilities: baseCaps},
			newlyEnrolled: true,
			want:          true,
		},
		{
			name:          "new enrollment with full status",
			agent:         &model.Agent{},
			msg:           fullStatusMsg(1),
			newlyEnrolled: true,
			want:          false,
		},
		{
			name:          "reconnect from disconnect seq 0",
			agent:         &model.Agent{LastCheckinStatus: "disconnected", SequenceNum: 10},
			msg:           &protobufs.AgentToServer{SequenceNum: 0, Capabilities: baseCaps},
			newlyEnrolled: false,
			want:          false,
		},
		{
			name:          "reconnect from disconnect seq continues",
			agent:         &model.Agent{LastCheckinStatus: "disconnected", SequenceNum: 10},
			msg:           &protobufs.AgentToServer{SequenceNum: 11, Capabilities: baseCaps},
			newlyEnrolled: false,
			want:          false,
		},
		{
			name:          "reconnect from disconnect unexpected seq",
			agent:         &model.Agent{LastCheckinStatus: "disconnected", SequenceNum: 10},
			msg:           &protobufs.AgentToServer{SequenceNum: 5, Capabilities: baseCaps},
			newlyEnrolled: false,
			want:          true,
		},
		{
			name:          "stored seq 0 incoming seq 0",
			agent:         &model.Agent{SequenceNum: 0, LastCheckinStatus: "online"},
			msg:           &protobufs.AgentToServer{SequenceNum: 0, Capabilities: baseCaps},
			newlyEnrolled: false,
			want:          true,
		},
		{
			name:          "stored seq 0 incoming seq 1 - happy path",
			agent:         &model.Agent{SequenceNum: 0, LastCheckinStatus: "online"},
			msg:           fullStatusMsg(1),
			newlyEnrolled: false,
			want:          false,
		},
		{
			name:          "online agent with gap",
			agent:         &model.Agent{SequenceNum: 5, LastCheckinStatus: "online"},
			msg:           &protobufs.AgentToServer{SequenceNum: 7, Capabilities: baseCaps},
			newlyEnrolled: false,
			want:          true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, shouldRequestFullState(tc.agent, tc.msg, tc.newlyEnrolled))
		})
	}
}

func TestHandleMessageReportFullState(t *testing.T) {
	baseCaps := uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus)

	//nolint:dupl // test cases
	cases := []struct {
		name      string
		getBulker func(t *testing.T) *ftesting.MockBulk
		msg       *protobufs.AgentToServer
		wantFlags uint64
	}{
		{
			name: "sequence gap sets ReportFullState flag",
			getBulker: func(t *testing.T) *ftesting.MockBulk {
				t.Helper()
				bulker := ftesting.NewMockBulk()
				agent := model.Agent{
					LastCheckinStatus: "online",
					SequenceNum:       5,
				}
				agentBytes, err := json.Marshal(agent)
				require.NoError(t, err)
				bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{ID: "agent-123", Source: agentBytes}}}}, nil)
				return bulker
			},
			msg: &protobufs.AgentToServer{
				SequenceNum:  7, // gap: expected 6
				Capabilities: baseCaps,
			},
			wantFlags: uint64(protobufs.ServerToAgentFlags_ServerToAgentFlags_ReportFullState),
		},
		{
			name: "sequential sequence number does not set flag",
			getBulker: func(t *testing.T) *ftesting.MockBulk {
				t.Helper()
				bulker := ftesting.NewMockBulk()
				agent := model.Agent{
					LastCheckinStatus: "online",
					SequenceNum:       5,
				}
				agentBytes, err := json.Marshal(agent)
				require.NoError(t, err)
				bulker.On("Search", mock.Anything, dl.FleetAgents, mock.Anything, mock.Anything).
					Return(&es.ResultT{HitsT: es.HitsT{Hits: []es.HitT{{ID: "agent-123", Source: agentBytes}}}}, nil)
				return bulker
			},
			msg: &protobufs.AgentToServer{
				SequenceNum:      6, // expected: 5 + 1
				Capabilities:     baseCaps,
				AgentDescription: &protobufs.AgentDescription{},
				Health:           &protobufs.ComponentHealth{Healthy: true},
			},
			wantFlags: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bulker := tc.getBulker(t)
			checker := &mockCheckin{}
			oa := &OpAMPT{bulk: bulker, bc: checker}

			agentUID := uuid.Must(uuid.NewV7())
			tc.msg.InstanceUid = agentUID.Bytes()
			zlog := zerolog.New(io.Discard)
			apiKey := &apikey.APIKey{ID: "test-key"}

			handler := oa.handleMessage(zlog, apiKey)
			resp := handler(t.Context(), nil, tc.msg)

			require.Nil(t, resp.ErrorResponse)
			require.Equal(t, tc.wantFlags, resp.Flags)
		})
	}
}
