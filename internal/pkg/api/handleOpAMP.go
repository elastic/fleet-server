// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/gofrs/uuid/v5"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"google.golang.org/protobuf/proto"
)

const (
	kOpAMPMod = "opAMP"
)

type OpAMPT struct {
	bulk  bulk.Bulk
	cache cache.Cache
	bc    *checkin.Bulk

	agentMetas map[string]localMetadata
}

func NewOpAMPT(
	bulker bulk.Bulk,
	cache cache.Cache,
	bc *checkin.Bulk,
) *OpAMPT {
	oa := &OpAMPT{
		bulk:       bulker,
		cache:      cache,
		bc:         bc,
		agentMetas: map[string]localMetadata{},
	}
	return oa
}

func (oa OpAMPT) handleOpAMP(zlog zerolog.Logger, r *http.Request, w http.ResponseWriter) error {
	apiKey, err := authAPIKey(r, oa.bulk, oa.cache)
	if err != nil {
		zlog.Debug().Err(err).Msg("unauthenticated opamp request")
		return err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &BadRequestErr{msg: "failed to read AgentToServer request body"}
	}
	defer r.Body.Close()

	var aToS protobufs.AgentToServer
	if err := proto.Unmarshal(body, &aToS); err != nil {
		return &BadRequestErr{msg: "failed to unmarshal AgentToServer message"}
	}

	instanceUID, err := uuid.FromBytes(aToS.InstanceUid)
	if err != nil {
		return &BadRequestErr{msg: "failed to parse instance_uid from AgentToServer message"}
	}
	zlog.Debug().
		Str("instance_uid", instanceUID.String()).
		Msg("received AgentToServer message from agent")

	// Check if Agent is "enrolled"; if it is, update it; otherwise, enroll it.
	isEnrolled, err := oa.isAgentEnrolled(zlog, instanceUID.String())
	if err != nil {
		return fmt.Errorf("failed to check if agent is enrolled: %w", err)
	}

	zlog.Debug().
		Bool("is_enrolled", isEnrolled).
		Str("agent_id", instanceUID.String()).
		Msg("agent enrollment status")
	if !isEnrolled {
		if err := oa.enrollAgent(zlog, instanceUID.String(), aToS, apiKey); err != nil {
			return fmt.Errorf("failed to enroll agent: %w", err)
		}
	}

	if err := oa.updateAgent(zlog, instanceUID.String(), aToS); err != nil {
		return fmt.Errorf("failed to update persisted Agent information: %w", err)
	}

	sToA := protobufs.ServerToAgent{}
	resp, err := proto.Marshal(&sToA)
	if err != nil {
		return fmt.Errorf("failed to marshal ServerToAgent response body: %w", err)
	}

	_, err = w.Write(resp)
	return err
}

func (oa OpAMPT) isAgentEnrolled(zlog zerolog.Logger, agentID string) (bool, error) {
	ctx := context.TODO()
	agent, err := dl.FindAgent(ctx, oa.bulk, dl.QueryAgentByID, dl.FieldID, agentID)
	if errors.Is(err, dl.ErrNotFound) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("failed to find agent: %w", err)
	}

	if agent.Id == "" {
		return false, nil
	}

	return true, nil
}

func (oa OpAMPT) enrollAgent(zlog zerolog.Logger, agentID string, aToS protobufs.AgentToServer, apiKey *apikey.APIKey) error {
	zlog.Debug().
		Str("agentID", agentID).
		Msg("enrolling agent")
	ctx := context.TODO()
	rec, err := dl.FindEnrollmentAPIKey(ctx, oa.bulk, dl.QueryEnrollmentAPIKeyByID, dl.FieldAPIKeyID, apiKey.ID)
	if err != nil {
		return fmt.Errorf("failed to find enrollment API key: %w", err)
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
		zlog.Debug().Str("agent_version", meta.Elastic.Agent.Version).Msg("extracted agent version")

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
		return fmt.Errorf("failed to marshal local metadata: %w", err)
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
		return err
	}

	zlog.Debug().
		Str("agent document", string(data)).
		Msg("creating .fleet-agents doc")
	if _, err = oa.bulk.Create(ctx, dl.FleetAgents, agentID, data, bulk.WithRefresh()); err != nil {
		return err
	}

	return nil
}

func (oa OpAMPT) updateAgent(zlog zerolog.Logger, agentID string, aToS protobufs.AgentToServer) error {
	zlog.Debug().
		Str("aToS", aToS.String()).
		Msg("updating .fleet-agents doc")

	initialOpts := make([]checkin.Option, 0)

	// Extract the health status from the health message if it exists.
	if aToS.Health != nil {
		initialOpts = append(initialOpts, checkin.WithStatus(aToS.Health.Status))
	}

	// Extract the unhealthy reason from the health message if it exists.
	if aToS.Health != nil && aToS.Health.LastError != "" {
		unhealthyReason := []string{aToS.Health.LastError}
		initialOpts = append(initialOpts, checkin.WithUnhealthyReason(&unhealthyReason))
	}

	return oa.bc.CheckIn(agentID, initialOpts...)
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
