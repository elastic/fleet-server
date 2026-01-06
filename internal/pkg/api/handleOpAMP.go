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
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"github.com/gofrs/uuid/v5"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/rs/zerolog"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"google.golang.org/protobuf/proto"
)

const (
	kOpAMPMod = "opAMP"
)

type OpAMPT struct {
	bulk  bulk.Bulk
	cache cache.Cache
	bc    *checkin.Bulk
}

func NewOpAMPT(
	bulker bulk.Bulk,
	cache cache.Cache,
	bc *checkin.Bulk,
) *OpAMPT {
	oa := &OpAMPT{
		bulk:  bulker,
		cache: cache,
		bc:    bc,
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
	if isEnrolled {
		if err := oa.updateAgent(zlog, instanceUID.String(), aToS); err != nil {
			return fmt.Errorf("failed to update persisted Agent information: %w", err)
		}
	} else {
		if err := oa.enrollAgent(zlog, instanceUID.String(), aToS, apiKey); err != nil {
			return fmt.Errorf("failed to enroll agent: %w", err)
		}
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
	agent := model.Agent{
		ESDocument: model.ESDocument{Id: agentID},
		Active:     true,
		EnrolledAt: now.UTC().Format(time.RFC3339),
		PolicyID:   rec.PolicyID,
		Agent: &model.AgentMetadata{
			ID: agentID,
		},
	}

	data, err := json.Marshal(agent)
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
		Msg("updating fleet-agents doc")

	initialOpts := []checkin.Option{
		checkin.WithSeqNo(sqn.SeqNo{int64(aToS.SequenceNum)}),
		//checkin.WithMessage(),
		//checkin.WithMeta(rawMeta),
		//checkin.WithComponents(rawComponents),
		//checkin.WithDeleteAudit(agent.AuditUnenrolledReason != "" || agent.UnenrolledAt != ""),
	}

	// Extract the agent version from the identifying attributes. However, agent description is
	// only sent if any of its fields, including identifying attributes, change.
	if aToS.AgentDescription != nil {
		var agentVersion string
		for _, ia := range aToS.AgentDescription.IdentifyingAttributes {
			switch ia.Key {
			case string(semconv.ServiceVersionKey):
				agentVersion = ia.String()
			}
		}
		initialOpts = append(initialOpts, checkin.WithVer(agentVersion))
	}

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
