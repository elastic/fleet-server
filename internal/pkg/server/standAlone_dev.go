// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build dev

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"github.com/rs/zerolog/log"
)

// standAloneSetup will ensure that the agent is enrolled.
func (f *Fleet) standAloneSetup(ctx context.Context, bulker bulk.Bulk, sm policy.SelfMonitor, policyID, agentID string) (*model.Agent, error) {
	log.Debug().Str("agent_id", agentID).Msg("stand-alone dev setup starting")
	err := sm.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to run self monitor for stand alone setup: %w", err)
	}
	policy := sm.Policy()
	// TODO use policy from self monitor
	// will need to happen as a bootstrapping step if it should occur here - otherwise we may want to fake revision id and coordinator id and update on checkin
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID)
	// Enroll the agent if it's not found
	if errors.Is(err, dl.ErrNotFound) || errors.Is(err, es.ErrIndexNotFound) {
		hostname, _ := os.Hostname()
		agentData := model.Agent{
			Active:               true,
			PolicyID:             policyID,
			PolicyRevisionIdx:    policy.RevisionIdx,
			PolicyCoordinatorIdx: policy.CoordinatorIdx,
			Type:                 "PERMANENT",
			EnrolledAt:           time.Now().UTC().Format(time.RFC3339),
			ActionSeqNo:          []int64{sqn.UndefinedSeqNo},
			Agent: &model.AgentMetadata{
				ID:      agentID,
				Version: f.bi.Version,
			},
			LocalMetadata: json.RawMessage(`{"host":{"hostname":"` + hostname + `"},"elastic":{"agent":{"id":"` + agentID + `","version":"` + f.bi.Version + `"}}}`),
		}
		p, err := json.Marshal(agentData)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal data for enrollment: %w", err)
		}
		_, err = bulker.Create(ctx, dl.FleetAgents, agentID, p, bulk.WithRefresh())
		if err != nil {
			return nil, fmt.Errorf("unable to create agent document for fleet-server mock/dev/fake agent: %w", err)
		}
		// sanity check
		agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID)
		if err != nil {
			return nil, fmt.Errorf("unable to find indexed agent: %w", err)
		}
		log.Debug().Str("agent_id", agentID).Msg("stand-alone dev setup agent indexed.")
		return &agent, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to find agent entry: %w", err)
	}
	log.Debug().Str("agent_id", agentID).Msg("stand-alone dev setup agent found.")
	return &agent, nil
}

func (f *Fleet) standAloneCheckin(agent *model.Agent, ct *api.CheckinT) runFunc {
	return func(ctx context.Context) error {
		tick := time.NewTimer(30 * time.Second) // fleet-server holds poll open for up to 5m
		defer tick.Stop()
		var ackToken string // TODO persistence?
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("standAloneCheckin ctx is done: %w", ctx.Err())
			case ts := <-tick.C:
				log.Info().Msg("self-checkin start")
				body := api.CheckinRequest{
					Status:   "HEALTHY",
					AckToken: ackToken,
					// TODO Metadata?
				}
				b, _ := json.Marshal(body)
				req, _ := http.NewRequestWithContext(ctx, "", "", bytes.NewReader(b))
				resp := newResponse()
				// TODO change logger?
				err := ct.ProcessRequest(log.Logger, resp, req, ts, agent, f.bi.Version)
				if err != nil {
					return err // log instead?
				}
				if resp.b.Len() < 1 {
					log.Warn().Msg("self-checkin returned no body")
					continue
				}
				rBody := api.CheckinResponse{}
				err = json.Unmarshal(resp.b.Bytes(), &rBody)
				if err != nil {
					log.Error().Err(err).Msg("self-checkin unable to unmarshal response")
					return err
				}
				ackToken = rBody.AckToken
				log.Info().Str("ackToken", ackToken).Int("action_count", len(rBody.Actions)).Msg("self-checkin success token")
				// TODO handle policy-change, unenroll, and settings actions? upgrade?
				log.Info().Msgf("self-checkin actions: %v", rBody.Actions)
				tick.Reset(30 * time.Second)
			}
		}
		log.Debug().Str("agent_id", agent.Agent.ID).Msg("exiting self-checkin")
		return nil
	}
}

type fakeResponse struct {
	status int
	h      http.Header
	b      bytes.Buffer
}

func newResponse() *fakeResponse {
	return &fakeResponse{
		h: http.Header{},
	}
}

func (r *fakeResponse) Header() http.Header {
	return r.h
}

func (r *fakeResponse) Write(p []byte) (int, error) {
	return r.b.Write(p)
}

func (r *fakeResponse) WriteHeader(status int) {
	r.status = status
}
