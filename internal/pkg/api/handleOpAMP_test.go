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

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
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

<<<<<<< HEAD
=======
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

>>>>>>> bc20c8b (fix: report server capabilities in OpAMP responses (#6829))
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

func getUnexportedField(v reflect.Value, name string) reflect.Value {
	field := v.FieldByName(name)
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
}
