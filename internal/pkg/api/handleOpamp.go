// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	opampserver "github.com/open-telemetry/opamp-go/server"
	"github.com/open-telemetry/opamp-go/server/types"
	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

//go:embed opamp_index_settings.json
var opampIndexSettings string

const (
	kOpAmpMod            = "opamp"
	kOpAmpDefaultPath    = "/v1/opamp"
	kOpAmpAgentType      = "opamp-agent"
	kOpAmpProtocolHTTP   = "http"
	kOpAmpStatusOnline   = "online"
	kOpAmpStatusHealthy  = "healthy"
	kOpAmpStatusDegraded = "degraded"
)

// OpAmpT handles OpAmp protocol connections from OpenTelemetry Collectors
type OpAmpT struct {
	cfg         *config.Server
	bulker      bulk.Bulk
	opampSrv    opampserver.OpAMPServer
	logger      zerolog.Logger
	handler     http.HandlerFunc
	connContext func(ctx context.Context, c net.Conn) context.Context
	indexOnce   sync.Once
	indexErr    error
}

// NewOpAmpT creates a new OpAmp handler instance
func NewOpAmpT(cfg *config.Server, bulker bulk.Bulk, logger zerolog.Logger) *OpAmpT {
	log := logger.With().Str("mod", kOpAmpMod).Logger()

	ot := &OpAmpT{
		cfg:    cfg,
		bulker: bulker,
		logger: log,
	}

	// Create opamp-go server with Fleet's logger adapter
	ot.opampSrv = opampserver.New(&opampLogger{logger: log})

	// Initialize the handler and connection context
	if err := ot.initHandler(); err != nil {
		log.Error().Err(err).Msg("Failed to initialize OpAmp handler")
	}

	return ot
}

// initHandler initializes the HTTP handler and connection context
func (ot *OpAmpT) initHandler() error {
	settings := opampserver.Settings{
		Callbacks: types.Callbacks{
			OnConnecting: ot.onConnecting,
		},
		EnableCompression: true,
	}

	handler, connCtx, err := ot.opampSrv.Attach(settings)
	if err != nil {
		return fmt.Errorf("failed to attach opamp server: %w", err)
	}

	// Store the handler wrapped as http.HandlerFunc
	ot.handler = func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}
	ot.connContext = connCtx

	return nil
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
// Returns nil if handler initialization failed
func (ot *OpAmpT) GetHTTPHandler() http.HandlerFunc {
	return ot.handler
}

// GetConnContext returns the connection context function required by opamp-go
// This should be used with http.Server.ConnContext to properly store
// the connection in the request context (required by opamp-go for plain HTTP mode)
// Returns nil if handler initialization failed
func (ot *OpAmpT) GetConnContext() func(ctx context.Context, c net.Conn) context.Context {
	return ot.connContext
}

// IsReady returns true if the handler was successfully initialized
func (ot *OpAmpT) IsReady() bool {
	return ot.handler != nil && ot.connContext != nil
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
	// Get logger from context if available, fall back to instance logger
	zlog := zerolog.Ctx(ctx)
	if zlog.GetLevel() == zerolog.Disabled {
		zlog = &ot.logger
	}

	// Validate instance_uid (must be 16 bytes UUID v7)
	if len(msg.InstanceUid) != 16 {
		zlog.Error().Int("uid_len", len(msg.InstanceUid)).Msg("Invalid instance_uid length")
		return &protobufs.ServerToAgent{
			ErrorResponse: &protobufs.ServerErrorResponse{
				Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_BadRequest,
				ErrorMessage: "instance_uid must be 16 bytes",
			},
		}
	}

	instanceUID := hex.EncodeToString(msg.InstanceUid)

	zlog.Debug().
		Str("instance_uid", instanceUID).
		Uint64("sequence_num", msg.SequenceNum).
		Uint64("capabilities", msg.Capabilities).
		Msg("Received OpAmp message")

	// Build Elasticsearch document from message
	doc, err := ot.buildAgentDocument(msg)
	if err != nil {
		zlog.Error().Err(err).Msg("Failed to build agent document")
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
		zlog.Error().Err(err).Str("instance_uid", instanceUID).Msg("Failed to write agent status")
		// Note: We don't return an error to the client here because ES write failures
		// shouldn't prevent the OpAmp protocol from functioning. The agent will retry
		// on its next poll interval.
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
		// Extract the body from the ConfigMap
		configMap := msg.EffectiveConfig.ConfigMap.ConfigMap[""]

		if len(configMap.Body) != 0 {
			bodyBytes := configMap.Body

			doc.OpAmp.EffectiveConfig = &model.OpAmpEffectiveConfig{
				ConfigMap: bodyBytes,
				Hash:      hex.EncodeToString(bodyBytes),
			}
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

// ensureIndex ensures the OpAmp agents index exists in Elasticsearch
// This is called once on the first write attempt
func (ot *OpAmpT) ensureIndex(ctx context.Context) error {
	ot.indexOnce.Do(func() {
		ot.indexErr = ot.createIndex(ctx)
	})
	return ot.indexErr
}

// createIndex creates the OpAmp agents index, deleting it first if it exists
func (ot *OpAmpT) createIndex(ctx context.Context) error {
	if ot.bulker == nil {
		return fmt.Errorf("bulker not configured")
	}

	client := ot.bulker.Client()
	if client == nil {
		return fmt.Errorf("elasticsearch client not available")
	}

	indexName := dl.OpAmpAgents

	// Check if index exists
	res, err := client.Indices.Exists(
		[]string{indexName},
		client.Indices.Exists.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("failed to check index existence: %w", err)
	}
	res.Body.Close()

	// If index exists (status 200), delete it first
	if res.StatusCode == http.StatusOK {
		ot.logger.Info().Str("index", indexName).Msg("Deleting existing OpAmp agents index")
		res, err = client.Indices.Delete(
			[]string{indexName},
			client.Indices.Delete.WithContext(ctx),
		)
		if err != nil {
			return fmt.Errorf("failed to delete index: %w", err)
		}
		res.Body.Close()
		if res.IsError() {
			return fmt.Errorf("failed to delete index: %s", res.String())
		}
	}

	// Create the index with settings and mappings
	ot.logger.Info().Str("index", indexName).Msg("Creating OpAmp agents index")
	res, err = client.Indices.Create(
		indexName,
		client.Indices.Create.WithContext(ctx),
		client.Indices.Create.WithBody(strings.NewReader(opampIndexSettings)),
	)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("failed to create index: %s", res.String())
	}

	ot.logger.Info().Str("index", indexName).Msg("OpAmp agents index created successfully")
	return nil
}

// writeAgentStatus writes or updates agent status in Elasticsearch
func (ot *OpAmpT) writeAgentStatus(ctx context.Context, instanceUID string, doc *model.OpAmpAgent) error {
	// Ensure index exists before first write
	if err := ot.ensureIndex(ctx); err != nil {
		ot.logger.Warn().Err(err).Msg("Failed to ensure OpAmp agents index exists")
		// Continue anyway - ES might auto-create the index
	}

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
