// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	opampserver "github.com/open-telemetry/opamp-go/server"
	"github.com/open-telemetry/opamp-go/server/types"
	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

const (
	kOpAmpMod           = "opamp"
	kOpAmpDefaultPath   = "/v1/opamp"
	kOpAmpAgentType     = "opamp-agent"
	kOpAmpProtocolHTTP  = "http"
	kOpAmpStatusOnline  = "online"
	kOpAmpStatusHealthy = "healthy"
	kOpAmpStatusDegraded = "degraded"
)

// OpAmpT handles OpAmp protocol connections from OpenTelemetry Collectors
type OpAmpT struct {
	cfg      *config.Server
	bulker   bulk.Bulk
	cache    cache.Cache
	opampSrv opampserver.OpAMPServer
	logger   zerolog.Logger
}

// NewOpAmpT creates a new OpAmp handler instance
func NewOpAmpT(cfg *config.Server, bulker bulk.Bulk, c cache.Cache) *OpAmpT {
	logger := zerolog.Nop().With().Str("mod", kOpAmpMod).Logger()
	ot := &OpAmpT{
		cfg:    cfg,
		bulker: bulker,
		cache:  c,
		logger: logger,
	}

	// Create opamp-go server with Fleet's logger adapter
	ot.opampSrv = opampserver.New(&opampLogger{logger: ot.logger})

	return ot
}

// SetLogger sets the logger for the OpAmp handler
func (ot *OpAmpT) SetLogger(logger zerolog.Logger) {
	ot.logger = logger.With().Str("mod", kOpAmpMod).Logger()
}

// opampLogger adapts zerolog to opamp-go's logger interface
type opampLogger struct {
	logger zerolog.Logger
}

func (l *opampLogger) Debugf(_ context.Context, format string, v ...interface{}) {
	l.logger.Debug().Msgf(format, v...)
}

func (l *opampLogger) Errorf(_ context.Context, format string, v ...interface{}) {
	l.logger.Error().Msgf(format, v...)
}

// GetHTTPHandler returns the HTTP handler function for integration with Fleet Server's router
// Rate limiting is handled by the router middleware
func (ot *OpAmpT) GetHTTPHandler() (http.HandlerFunc, error) {
	settings := opampserver.Settings{
		Callbacks: types.Callbacks{
			OnConnecting: ot.onConnecting,
		},
		EnableCompression: true,
	}

	handler, _, err := ot.opampSrv.Attach(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to attach opamp server: %w", err)
	}

	// Wrap the opamp handler to match http.HandlerFunc signature
	return func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}, nil
}

// GetPath returns the configured OpAmp endpoint path
func (ot *OpAmpT) GetPath() string {
	if ot.cfg.OpAmp.Path != "" {
		return ot.cfg.OpAmp.Path
	}
	return kOpAmpDefaultPath
}

// IsEnabled returns whether OpAmp is enabled in configuration
func (ot *OpAmpT) IsEnabled() bool {
	return ot.cfg.OpAmp.Enabled
}

// onConnecting is called for each new OpAmp connection
func (ot *OpAmpT) onConnecting(request *http.Request) types.ConnectionResponse {
	// Extract and validate authentication (API key or anonymous)
	// For anonymous auth fallback, accept all connections
	// For API key auth, validate against Elasticsearch here
	apiKey := request.Header.Get("Authorization")
	if apiKey != "" {
		// TODO: Validate API key using existing apikey package
		// For now, log that auth was provided
		ot.logger.Debug().
			Str("remote_addr", request.RemoteAddr).
			Msg("OpAmp connection with authorization header")
	}

	ot.logger.Debug().
		Str("remote_addr", request.RemoteAddr).
		Str("user_agent", request.UserAgent()).
		Msg("OpAmp connection accepted")

	return types.ConnectionResponse{
		Accept: true,
		ConnectionCallbacks: types.ConnectionCallbacks{
			OnConnected:       ot.onConnected,
			OnMessage:         ot.onMessage,
			OnConnectionClose: ot.onConnectionClose,
		},
	}
}

func (ot *OpAmpT) onConnected(_ context.Context, _ types.Connection) {
	ot.logger.Info().Msg("OpAmp agent connected")
}

func (ot *OpAmpT) onConnectionClose(_ types.Connection) {
	ot.logger.Info().Msg("OpAmp agent disconnected")
}

// onMessage processes incoming AgentToServer messages
func (ot *OpAmpT) onMessage(
	ctx context.Context,
	_ types.Connection,
	msg *protobufs.AgentToServer,
) *protobufs.ServerToAgent {
	// Validate instance_uid (must be 16 bytes UUID v7)
	if len(msg.InstanceUid) != 16 {
		ot.logger.Error().Int("uid_len", len(msg.InstanceUid)).Msg("Invalid instance_uid length")
		return &protobufs.ServerToAgent{
			ErrorResponse: &protobufs.ServerErrorResponse{
				Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_BadRequest,
				ErrorMessage: "instance_uid must be 16 bytes",
			},
		}
	}

	instanceUID := hex.EncodeToString(msg.InstanceUid)

	ot.logger.Debug().
		Str("instance_uid", instanceUID).
		Uint64("sequence_num", msg.SequenceNum).
		Uint64("capabilities", msg.Capabilities).
		Msg("Received OpAmp message")

	// Build Elasticsearch document from message
	doc, err := ot.buildAgentDocument(msg)
	if err != nil {
		ot.logger.Error().Err(err).Msg("Failed to build agent document")
		return &protobufs.ServerToAgent{
			InstanceUid: msg.InstanceUid,
			ErrorResponse: &protobufs.ServerErrorResponse{
				Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_Unknown,
				ErrorMessage: err.Error(),
			},
		}
	}

	// Write to Elasticsearch
	if err := ot.writeAgentStatus(ctx, instanceUID, doc); err != nil {
		ot.logger.Error().Err(err).Str("instance_uid", instanceUID).Msg("Failed to write agent status")
	}

	// Build read-only response (no config push)
	return &protobufs.ServerToAgent{
		InstanceUid: msg.InstanceUid,
		Capabilities: uint64(
			protobufs.ServerCapabilities_ServerCapabilities_AcceptsStatus |
				protobufs.ServerCapabilities_ServerCapabilities_AcceptsEffectiveConfig,
		),
	}
}

// buildAgentDocument converts OpAmp protobuf message to ES document
func (ot *OpAmpT) buildAgentDocument(msg *protobufs.AgentToServer) (*model.OpAmpAgent, error) {
	instanceUID := hex.EncodeToString(msg.InstanceUid)
	now := time.Now().UTC()

	doc := &model.OpAmpAgent{
		Timestamp: now,
		OpAmp: model.OpAmpData{
			Agent: model.OpAmpAgentInfo{
				InstanceUID: instanceUID,
			},
			Status:       kOpAmpStatusOnline,
			SequenceNum:  msg.SequenceNum,
			Capabilities: decodeCapabilities(msg.Capabilities),
		},
		Connection: model.ConnectionData{
			LastSeen: now,
			Protocol: kOpAmpProtocolHTTP,
		},
		Agent: model.AgentInfo{
			ID:   instanceUID,
			Type: kOpAmpAgentType,
		},
	}

	// Extract agent description
	if msg.AgentDescription != nil {
		doc.OpAmp.Agent.IdentifyingAttributes = keyValuesToMap(msg.AgentDescription.IdentifyingAttributes)
		doc.OpAmp.Agent.NonIdentifyingAttributes = keyValuesToMap(msg.AgentDescription.NonIdentifyingAttributes)

		// Extract common fields for ECS compatibility
		if name, ok := doc.OpAmp.Agent.IdentifyingAttributes["service.name"]; ok {
			doc.Agent.Name = name
			doc.OpAmp.Agent.Type = name
		}
		if version, ok := doc.OpAmp.Agent.IdentifyingAttributes["service.version"]; ok {
			doc.Agent.Version = version
			doc.OpAmp.Agent.Version = version
		}

		// Extract host info from non-identifying attributes
		if hostname, ok := doc.OpAmp.Agent.NonIdentifyingAttributes["host.name"]; ok {
			doc.Host.Hostname = hostname
		}
		if osType, ok := doc.OpAmp.Agent.NonIdentifyingAttributes["os.type"]; ok {
			if doc.Host.OS == nil {
				doc.Host.OS = &model.OSInfo{}
			}
			doc.Host.OS.Type = osType
		}
	}

	// Extract health status
	if msg.Health != nil {
		doc.OpAmp.Health = convertHealth(msg.Health)
		if msg.Health.Healthy {
			doc.OpAmp.Status = kOpAmpStatusHealthy
		} else {
			doc.OpAmp.Status = kOpAmpStatusDegraded
		}
	}

	// Extract effective config (store hash, optionally full config)
	if msg.EffectiveConfig != nil && msg.EffectiveConfig.ConfigMap != nil {
		configBytes, _ := json.Marshal(msg.EffectiveConfig.ConfigMap.ConfigMap)
		doc.OpAmp.EffectiveConfig = &model.OpAmpEffectiveConfig{
			ConfigMap: configBytes,
		}
	}

	// Extract remote config status
	if msg.RemoteConfigStatus != nil {
		doc.OpAmp.RemoteConfigStatus = &model.OpAmpConfigStatus{
			LastConfigHash: hex.EncodeToString(msg.RemoteConfigStatus.LastRemoteConfigHash),
			Status:         msg.RemoteConfigStatus.Status.String(),
			ErrorMessage:   msg.RemoteConfigStatus.ErrorMessage,
		}
	}

	return doc, nil
}

// keyValuesToMap converts protobuf KeyValue slice to map
func keyValuesToMap(kvs []*protobufs.KeyValue) map[string]string {
	result := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		if kv.Value != nil {
			if sv := kv.Value.GetStringValue(); sv != "" {
				result[kv.Key] = sv
			}
		}
	}
	return result
}

// decodeCapabilities converts capability bitmask to human-readable strings
func decodeCapabilities(caps uint64) []string {
	var result []string
	capMap := map[uint64]string{
		uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus):          "ReportsStatus",
		uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig):    "AcceptsRemoteConfig",
		uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig): "ReportsEffectiveConfig",
		uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth):          "ReportsHealth",
	}
	for mask, name := range capMap {
		if caps&mask != 0 {
			result = append(result, name)
		}
	}
	return result
}

// convertHealth recursively converts protobuf health to model
func convertHealth(h *protobufs.ComponentHealth) *model.OpAmpHealth {
	if h == nil {
		return nil
	}
	health := &model.OpAmpHealth{
		Healthy:            h.Healthy,
		StartTimeUnixNano:  h.StartTimeUnixNano,
		LastError:          h.LastError,
		Status:             h.Status,
		StatusTimeUnixNano: h.StatusTimeUnixNano,
	}
	if len(h.ComponentHealthMap) > 0 {
		health.ComponentHealth = make(map[string]*model.OpAmpHealth)
		for name, ch := range h.ComponentHealthMap {
			health.ComponentHealth[name] = convertHealth(ch)
		}
	}
	return health
}

// writeAgentStatus writes or updates agent status in Elasticsearch
func (ot *OpAmpT) writeAgentStatus(ctx context.Context, instanceUID string, doc *model.OpAmpAgent) error {
	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	// Use Update with doc_as_upsert for idempotent writes
	updateBody := map[string]interface{}{
		"doc":           json.RawMessage(body),
		"doc_as_upsert": true,
	}
	updateBytes, err := json.Marshal(updateBody)
	if err != nil {
		return fmt.Errorf("failed to marshal update body: %w", err)
	}

	err = ot.bulker.Update(
		ctx,
		dl.OpAmpAgents,
		instanceUID,
		updateBytes,
		bulk.WithRefresh(),
		bulk.WithRetryOnConflict(3),
	)
	if err != nil {
		return fmt.Errorf("failed to update agent in ES: %w", err)
	}

	ot.logger.Debug().
		Str("instance_uid", instanceUID).
		Msg("Agent status written to Elasticsearch")

	return nil
}

