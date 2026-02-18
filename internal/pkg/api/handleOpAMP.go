// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/gofrs/uuid/v5"
	"github.com/open-telemetry/opamp-go/protobufs"
	oaServer "github.com/open-telemetry/opamp-go/server"
	"github.com/open-telemetry/opamp-go/server/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

const (
	kOpAMPMod = "opAMP"
)

type OpAMPT struct {
	cfg   *config.Server
	bulk  bulk.Bulk
	cache cache.Cache
	bc    *checkin.Bulk

	srv     oaServer.OpAMPServer
	handler oaServer.HTTPHandlerFunc
	connCtx oaServer.ConnContext

	agentMetas map[string]localMetadata
}

func NewOpAMPT(
	ctx context.Context,
	cfg *config.Server,
	bulker bulk.Bulk,
	cache cache.Cache,
	bc *checkin.Bulk,
) *OpAMPT {
	oa := &OpAMPT{
		cfg:        cfg,
		bulk:       bulker,
		cache:      cache,
		bc:         bc,
		srv:        oaServer.New(nil),
		agentMetas: map[string]localMetadata{},
	}

	return oa
}

func (oa *OpAMPT) Init() error {
	settings := oaServer.Settings{
		Callbacks: types.Callbacks{
			OnConnecting: func(request *http.Request) types.ConnectionResponse {
				zlog := hlog.FromRequest(request).With().
					Str("mod", kOpAMPMod).
					Logger()

				apiKey, err := authAPIKey(request, oa.bulk, oa.cache)
				if errors.Is(err, apikey.ErrElasticsearchAuthLimit) {
					zlog.Warn().Err(err).Msg("elasticsearch rate limit on opamp request")
					return types.ConnectionResponse{
						Accept:         false,
						HTTPStatusCode: http.StatusTooManyRequests,
						HTTPResponseHeader: map[string]string{
							"Content-Type": "application/x-protobuf",
						},
					}
				}
				if err != nil {
					zlog.Warn().Err(err).Msg("unauthenticated opamp request")
					return types.ConnectionResponse{
						Accept:         false,
						HTTPStatusCode: http.StatusUnauthorized,
						HTTPResponseHeader: map[string]string{
							"Content-Type": "application/x-protobuf",
						},
					}
				}

				zlog.Debug().Msg("authenticated opamp request")

				// Setup connection callbacks.
				connectionCallbacks := types.ConnectionCallbacks{
					OnConnected: func(ctx context.Context, conn types.Connection) {
						zlog.Debug().Msg("opAMP client connected")
					},
					OnConnectionClose: func(conn types.Connection) {
						zlog.Debug().Msg("opAMP client disconnected")
					},
					OnMessage: oa.handleMessage(zlog, apiKey),
					OnReadMessageError: func(conn types.Connection, mt int, msgByte []byte, err error) {
						zlog.Error().Err(err).Int("message_type", mt).Msg("failed to read opAMP message")
					},
					OnMessageResponseError: func(conn types.Connection, message *protobufs.ServerToAgent, err error) {
						zlog.Error().Err(err).Msg("failed to send opAMP response")
					},
				}
				connectionCallbacks.SetDefaults() // set defaults for other callbacks

				return types.ConnectionResponse{
					Accept:              true,
					ConnectionCallbacks: connectionCallbacks,
				}
			},
		},
		EnableCompression: true,
	}

	handler, connCtx, err := oa.srv.Attach(settings)
	if err != nil {
		return fmt.Errorf("failed to attach opAMP server: %w", err)
	}

	oa.handler = handler
	oa.connCtx = connCtx
	return nil
}

func (oa *OpAMPT) Enabled() bool {
	return oa.cfg.Features.EnableOpAMP
}

func (oa *OpAMPT) handleMessage(zlog zerolog.Logger, apiKey *apikey.APIKey) func(ctx context.Context, conn types.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
	return func(ctx context.Context, conn types.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
		instanceUID, err := uuid.FromBytes(message.InstanceUid)
		if err != nil {
			return &protobufs.ServerToAgent{
				ErrorResponse: &protobufs.ServerErrorResponse{
					Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_BadRequest,
					ErrorMessage: "failed to parse instance_uid from AgentToServer message",
				},
			}
		}

		zlog.Debug().
			Str("instance_uid", instanceUID.String()).
			Str("aToS", message.String()).
			Msg("received AgentToServer message from agent")

		// Check if Agent is "enrolled"; if it is, update it; otherwise, enroll it.
		agent, err := oa.findEnrolledAgent(ctx, zlog, instanceUID.String())
		if err != nil {
			return &protobufs.ServerToAgent{
				InstanceUid: instanceUID.Bytes(),
				ErrorResponse: &protobufs.ServerErrorResponse{
					Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_Unavailable,
					ErrorMessage: fmt.Sprintf("failed to check if agent is enrolled: %v", err),
				},
			}
		}

		zlog.Debug().
			Bool("is_enrolled", agent != nil).
			Str("opamp.agent.uid", instanceUID.String()).
			Msg("agent enrollment status")

		if agent == nil {
			if agent, err = oa.enrollAgent(zlog, instanceUID.String(), message, apiKey); err != nil {
				return &protobufs.ServerToAgent{
					InstanceUid: instanceUID.Bytes(),
					ErrorResponse: &protobufs.ServerErrorResponse{
						Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_Unavailable,
						ErrorMessage: fmt.Sprintf("failed to enroll agent: %v", err),
					},
				}
			}
		}

		if err := oa.updateAgent(zlog, agent, message); err != nil {
			return &protobufs.ServerToAgent{
				InstanceUid: instanceUID.Bytes(),
				ErrorResponse: &protobufs.ServerErrorResponse{
					Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_Unavailable,
					ErrorMessage: fmt.Sprintf("failed to update persisted Agent information: %v", err),
				},
			}
		}

		// Empty message for now since we're only using OpAMP for monitoring.
		sToA := protobufs.ServerToAgent{
			InstanceUid: instanceUID.Bytes(),
		}

		zlog.Debug().Str("resp", sToA.String()).Msg("sending ServerToAgent response")
		return &sToA
	}
}

func (oa *OpAMPT) findEnrolledAgent(ctx context.Context, _ zerolog.Logger, agentID string) (*model.Agent, error) {
	agent, err := dl.FindAgent(ctx, oa.bulk, dl.QueryAgentByID, dl.FieldID, agentID)
	if errors.Is(err, dl.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to find agent: %w", err)
	}

	if agent.Id == "" {
		return nil, nil
	}

	return &agent, nil
}

func (oa *OpAMPT) enrollAgent(zlog zerolog.Logger, agentID string, aToS *protobufs.AgentToServer, apiKey *apikey.APIKey) (*model.Agent, error) {
	zlog.Debug().
		Str("opamp.agent.uid", agentID).
		Msg("enrolling agent")
	ctx := context.TODO()
	rec, err := dl.FindEnrollmentAPIKey(ctx, oa.bulk, dl.QueryEnrollmentAPIKeyByID, dl.FieldAPIKeyID, apiKey.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to find enrollment API key: %w", err)
	}

	now := time.Now()

	// Extract the agent version from the agent description's identifying attributes. Also, extract
	// the hostname from the agent description's non-identifying attributes. However, the agent
	// description is only sent if any of its fields change.
	meta := localMetadata{}
	meta.Elastic.Agent.ID = agentID
	if aToS.AgentDescription != nil {
		// Extract agent version
		for _, ia := range aToS.AgentDescription.IdentifyingAttributes {
			switch attribute.Key(ia.Key) {
			case semconv.ServiceVersionKey:
				meta.Elastic.Agent.Version = ia.GetValue().GetStringValue()
			}
		}
		zlog.Debug().Str("opamp.agent.version", meta.Elastic.Agent.Version).Msg("extracted agent version")

		// Extract hostname
		for _, nia := range aToS.AgentDescription.NonIdentifyingAttributes {
			switch attribute.Key(nia.Key) {
			case semconv.HostNameKey:
				hostname := nia.GetValue().GetStringValue()
				meta.Host.Name = hostname
				meta.Host.Hostname = hostname
			}
		}
		zlog.Debug().Str("hostname", meta.Host.Hostname).Msg("extracted hostname")
	}

	// Update local metadata if something has changed
	data, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal local metadata: %w", err)
	}

	zlog.Debug().RawJSON("meta", data).Msg("updating local metadata")

	agent := model.Agent{
		ESDocument: model.ESDocument{Id: agentID},
		Active:     true,
		EnrolledAt: now.UTC().Format(time.RFC3339),
		PolicyID:   rec.PolicyID,
		Agent: &model.AgentMetadata{
			ID: agentID,
		},
		LocalMetadata: data,
	}

	data, err = json.Marshal(agent)
	if err != nil {
		return nil, err
	}

	zlog.Debug().
		Str("agent document", string(data)).
		Msg("creating .fleet-agents doc")
	if _, err = oa.bulk.Create(ctx, dl.FleetAgents, agentID, data, bulk.WithRefresh()); err != nil {
		return nil, err
	}

	return &agent, nil
}

func (oa *OpAMPT) updateAgent(zlog zerolog.Logger, agent *model.Agent, aToS *protobufs.AgentToServer) error {
	zlog.Debug().Msg("updating .fleet-agents doc")

	initialOpts := make([]checkin.Option, 0)

	// Extract the health status from the health message if it exists.
	if aToS.Health != nil {
		initialOpts = append(initialOpts, checkin.WithStatus(aToS.Health.Status))

		// Extract the unhealthy reason from the health message if it exists.
		if aToS.Health.LastError != "" {
			unhealthyReason := []string{aToS.Health.LastError}
			initialOpts = append(initialOpts, checkin.WithUnhealthyReason(&unhealthyReason))
		}
	}

	return oa.bc.CheckIn(agent.Id, initialOpts...)
}

type localMetadata struct {
	Elastic struct {
		Agent struct {
			ID      string `json:"id,omitempty"`
			Version string `json:"version,omitempty"`
		} `json:"agent,omitempty"`
	} `json:"elastic,omitempty"`
	Host struct {
		Hostname string `json:"hostname,omitempty"`
		Name     string `json:"name,omitempty"`
	} `json:"host,omitempty"`
}
