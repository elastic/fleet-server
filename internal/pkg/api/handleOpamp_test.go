// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/open-telemetry/opamp-go/client"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
)

// mockBulker implements bulk.Bulk interface for testing
type mockBulker struct {
	mock.Mock
	bulk.Bulk
}

func (m *mockBulker) Update(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) error {
	args := m.Called(ctx, index, id, body, opts)
	return args.Error(0)
}

// Client returns nil for testing - index creation will be skipped
func (m *mockBulker) Client() *elasticsearch.Client {
	return nil
}

// testClientLogger adapts testing.T to opamp-go client's Logger interface
type testClientLogger struct {
	t *testing.T
}

func (l *testClientLogger) Debugf(_ context.Context, format string, v ...interface{}) {
	l.t.Logf("[DEBUG] "+format, v...)
}

func (l *testClientLogger) Errorf(_ context.Context, format string, v ...interface{}) {
	l.t.Logf("[ERROR] "+format, v...)
}

func TestOpAmpHandler_BuildAgentDocument(t *testing.T) {
	cfg := &config.Server{}
	ot := NewOpAmpT(cfg, nil, zerolog.Nop())

	instanceUID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	msg := &protobufs.AgentToServer{
		InstanceUid: instanceUID,
		SequenceNum: 42,
		AgentDescription: &protobufs.AgentDescription{
			IdentifyingAttributes: []*protobufs.KeyValue{
				{Key: "service.name", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "my-collector"}}},
			},
		},
		Health: &protobufs.ComponentHealth{
			Healthy:   false,
			LastError: "connection refused",
		},
	}

	doc, err := ot.buildAgentDocument(msg)
	require.NoError(t, err)

	assert.Equal(t, "0102030405060708090a0b0c0d0e0f10", doc.OpAmp.Agent.InstanceUID)
	assert.Equal(t, uint64(42), doc.OpAmp.SequenceNum)
	assert.Equal(t, "my-collector", doc.Agent.Name)
	assert.Equal(t, "degraded", doc.OpAmp.Status)
	assert.False(t, doc.OpAmp.Health.Healthy)
	assert.Equal(t, "connection refused", doc.OpAmp.Health.LastError)
}

func TestOpAmpHandler_BuildAgentDocument_WithAllFields(t *testing.T) {
	cfg := &config.Server{}
	ot := NewOpAmpT(cfg, nil, zerolog.Nop())

	instanceUID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	msg := &protobufs.AgentToServer{
		InstanceUid: instanceUID,
		SequenceNum: 100,
		Capabilities: uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig),
		AgentDescription: &protobufs.AgentDescription{
			IdentifyingAttributes: []*protobufs.KeyValue{
				{Key: "service.name", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "otel-collector"}}},
				{Key: "service.version", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "0.90.0"}}},
			},
			NonIdentifyingAttributes: []*protobufs.KeyValue{
				{Key: "host.name", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "test-host.local"}}},
				{Key: "os.type", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "linux"}}},
			},
		},
		Health: &protobufs.ComponentHealth{
			Healthy:           true,
			StartTimeUnixNano: uint64(1000000000000),
			Status:            "running",
		},
		EffectiveConfig: &protobufs.EffectiveConfig{
			ConfigMap: &protobufs.AgentConfigMap{
				ConfigMap: map[string]*protobufs.AgentConfigFile{
					"": {Body: []byte("receivers:\n  otlp:\n")},
				},
			},
		},
	}

	doc, err := ot.buildAgentDocument(msg)
	require.NoError(t, err)

	// Verify instance UID
	assert.Equal(t, "0102030405060708090a0b0c0d0e0f10", doc.OpAmp.Agent.InstanceUID)

	// Verify sequence number
	assert.Equal(t, uint64(100), doc.OpAmp.SequenceNum)

	// Verify capabilities
	assert.Contains(t, doc.OpAmp.Capabilities, "ReportsStatus")
	assert.Contains(t, doc.OpAmp.Capabilities, "ReportsHealth")
	assert.Contains(t, doc.OpAmp.Capabilities, "ReportsEffectiveConfig")

	// Verify agent info from identifying attributes
	assert.Equal(t, "otel-collector", doc.Agent.Name)
	assert.Equal(t, "0.90.0", doc.Agent.Version)

	// Verify host info from non-identifying attributes
	assert.Equal(t, "test-host.local", doc.Host.Hostname)
	assert.NotNil(t, doc.Host.OS)
	assert.Equal(t, "linux", doc.Host.OS.Type)

	// Verify health
	assert.True(t, doc.OpAmp.Health.Healthy)
	assert.Equal(t, "running", doc.OpAmp.Health.Status)
	assert.Equal(t, uint64(1000000000000), doc.OpAmp.Health.StartTimeUnixNano)

	// Verify effective config (when present)
	assert.NotNil(t, doc.OpAmp.EffectiveConfig)

	// Verify computed status
	assert.Equal(t, "healthy", doc.OpAmp.Status)
}

func TestOpAmpHandler_BuildAgentDocument_MinimalMessage(t *testing.T) {
	cfg := &config.Server{}
	ot := NewOpAmpT(cfg, nil, zerolog.Nop())

	instanceUID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	msg := &protobufs.AgentToServer{
		InstanceUid: instanceUID,
		SequenceNum: 1,
	}

	doc, err := ot.buildAgentDocument(msg)
	require.NoError(t, err)

	assert.Equal(t, "0102030405060708090a0b0c0d0e0f10", doc.OpAmp.Agent.InstanceUID)
	assert.Equal(t, uint64(1), doc.OpAmp.SequenceNum)
	assert.Equal(t, "online", doc.OpAmp.Status) // Default status when no health info
}

// TestOpAmpWithRealClient tests with the actual opamp-go client library
// This is the most realistic test of whether the full flow works end-to-end
func TestOpAmpWithRealClient(t *testing.T) {
	// Setup mock bulker to capture calls
	mockBulk := new(mockBulker)
	mockBulk.On("Update", mock.Anything, "content-fleet-opamp-agents", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	cfg := &config.Server{
		OpAmp: config.OpAmpConfig{
			Enabled: true,
			Path:    "/v1/opamp",
		},
	}

	// Create handler
	ot := NewOpAmpT(cfg, mockBulk, zerolog.Nop())
	require.True(t, ot.IsReady(), "Handler should be ready")
	handler := ot.GetHTTPHandler()
	require.NotNil(t, handler, "HTTP handler should not be nil")
	connCtx := ot.GetConnContext()
	require.NotNil(t, connCtx, "ConnContext function should not be nil")

	// Start a real HTTP server with proper ConnContext for opamp-go
	// opamp-go requires the connection to be stored in the request context
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port

	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	server := &http.Server{
		Handler: http.HandlerFunc(handler),
		// Use the ConnContext function returned by opamp-go to properly store the connection
		ConnContext: connCtx,
	}

	// Start server in background using the listener
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Close()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create channels to signal connection events
	connectedCh := make(chan struct{}, 1)
	errorCh := make(chan *protobufs.ServerErrorResponse, 1)

	// Create OpAmp HTTP client with our test logger
	opampClient := client.NewHTTP(&testClientLogger{t: t})

	// Generate a random instance UID
	var instanceUID types.InstanceUid
	_, err = rand.Read(instanceUID[:])
	require.NoError(t, err)

	// Configure client callbacks
	settings := types.StartSettings{
		OpAMPServerURL: serverURL,
		InstanceUid:    instanceUID,
		Callbacks: types.Callbacks{
			OnConnect: func(ctx context.Context) {
				t.Log("Client connected to server")
				select {
				case connectedCh <- struct{}{}:
				default:
				}
			},
			OnConnectFailed: func(ctx context.Context, err error) {
				t.Logf("Client connection failed: %v", err)
			},
			OnError: func(ctx context.Context, err *protobufs.ServerErrorResponse) {
				t.Logf("Server returned error: %v", err)
				select {
				case errorCh <- err:
				default:
				}
			},
			OnMessage: func(ctx context.Context, msg *types.MessageData) {
				t.Log("Client received message from server")
			},
		},
	}

	// Set agent description BEFORE starting
	err = opampClient.SetAgentDescription(&protobufs.AgentDescription{
		IdentifyingAttributes: []*protobufs.KeyValue{
			{Key: "service.name", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "test-otel-collector"}}},
			{Key: "service.version", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "0.90.0"}}},
		},
		NonIdentifyingAttributes: []*protobufs.KeyValue{
			{Key: "host.name", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "test-host.local"}}},
			{Key: "os.type", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "darwin"}}},
		},
	})
	require.NoError(t, err)

	// Set health status
	err = opampClient.SetHealth(&protobufs.ComponentHealth{
		Healthy:           true,
		StartTimeUnixNano: uint64(time.Now().UnixNano()),
		Status:            "running",
	})
	require.NoError(t, err)

	// Start client - this will send the first AgentToServer message
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = opampClient.Start(ctx, settings)
	require.NoError(t, err)

	// Wait for connection (with timeout)
	select {
	case <-connectedCh:
		t.Log("✅ Successfully connected to OpAmp server")
	case serverErr := <-errorCh:
		t.Fatalf("Server returned error: %v", serverErr)
	case <-ctx.Done():
		t.Fatal("Timed out waiting for connection")
	}

	// Stop client gracefully
	err = opampClient.Stop(context.Background())
	require.NoError(t, err)

	// Verify bulker was called to persist data
	// Give a small delay for async processing
	time.Sleep(100 * time.Millisecond)
	mockBulk.AssertCalled(t, "Update", mock.Anything, "content-fleet-opamp-agents", mock.Anything, mock.Anything, mock.Anything)

	t.Log("✅ Full OpAmp client-server flow completed successfully!")
}

func TestDecodeCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		caps     uint64
		expected []string
	}{
		{
			name:     "no capabilities",
			caps:     0,
			expected: nil,
		},
		{
			name:     "reports status",
			caps:     uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus),
			expected: []string{"ReportsStatus"},
		},
		{
			name: "multiple capabilities",
			caps: uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus) |
				uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth),
			expected: []string{"ReportsStatus", "ReportsHealth"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeCapabilities(tt.caps)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.ElementsMatch(t, tt.expected, result)
			}
		})
	}
}

func TestKeyValuesToMap(t *testing.T) {
	tests := []struct {
		name     string
		input    []*protobufs.KeyValue
		expected map[string]string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: map[string]string{},
		},
		{
			name:     "empty input",
			input:    []*protobufs.KeyValue{},
			expected: map[string]string{},
		},
		{
			name: "string values",
			input: []*protobufs.KeyValue{
				{
					Key: "service.name",
					Value: &protobufs.AnyValue{
						Value: &protobufs.AnyValue_StringValue{StringValue: "otel-collector"},
					},
				},
				{
					Key: "service.version",
					Value: &protobufs.AnyValue{
						Value: &protobufs.AnyValue_StringValue{StringValue: "1.0.0"},
					},
				},
			},
			expected: map[string]string{
				"service.name":    "otel-collector",
				"service.version": "1.0.0",
			},
		},
		{
			name: "empty string value skipped",
			input: []*protobufs.KeyValue{
				{
					Key: "service.name",
					Value: &protobufs.AnyValue{
						Value: &protobufs.AnyValue_StringValue{StringValue: ""},
					},
				},
			},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := keyValuesToMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertHealth(t *testing.T) {
	tests := []struct {
		name     string
		input    *protobufs.ComponentHealth
		expected bool // just check healthy field for simplicity
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: false,
		},
		{
			name: "healthy",
			input: &protobufs.ComponentHealth{
				Healthy: true,
			},
			expected: true,
		},
		{
			name: "unhealthy",
			input: &protobufs.ComponentHealth{
				Healthy:   false,
				LastError: "connection failed",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertHealth(tt.input)
			if tt.input == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected, result.Healthy)
			}
		})
	}
}

func TestIsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Server
		expected bool
	}{
		{
			name: "enabled",
			cfg: &config.Server{
				OpAmp: config.OpAmpConfig{
					Enabled: true,
				},
			},
			expected: true,
		},
		{
			name: "disabled",
			cfg: &config.Server{
				OpAmp: config.OpAmpConfig{
					Enabled: false,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ot := NewOpAmpT(tt.cfg, nil, zerolog.Nop())
			assert.Equal(t, tt.expected, ot.IsEnabled())
		})
	}
}

func TestGetPath(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Server
		expected string
	}{
		{
			name: "custom path",
			cfg: &config.Server{
				OpAmp: config.OpAmpConfig{
					Path: "/custom/opamp",
				},
			},
			expected: "/custom/opamp",
		},
		{
			name: "empty path uses default",
			cfg: &config.Server{
				OpAmp: config.OpAmpConfig{
					Path: "",
				},
			},
			expected: kOpAmpDefaultPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ot := NewOpAmpT(tt.cfg, nil, zerolog.Nop())
			assert.Equal(t, tt.expected, ot.GetPath())
		})
	}
}

func TestIsReady(t *testing.T) {
	cfg := &config.Server{}
	ot := NewOpAmpT(cfg, nil, zerolog.Nop())

	// Handler should be ready after initialization
	assert.True(t, ot.IsReady())
	assert.NotNil(t, ot.GetHTTPHandler())
	assert.NotNil(t, ot.GetConnContext())
}
