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

func (f *Fleet) standAloneSetup(ctx context.Context, bulker bulk.Bulk, sm policy.SelfMonitor, policyID, agentID string) (*model.Agent, error) {
	err := sm.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to run self monitor for stand alone setup: %w", err)
	}
	policy := sm.Policy()
	log.Debug().Msgf("Policy Data: %s", string(policy.Data))
	// TODO use policy from self monitor
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID)
	// Enroll the agent if it's not found
	if errors.Is(err, dl.ErrNotFound) || errors.Is(err, es.ErrIndexNotFound) {
		hostname, _ := os.Hostname()
		agentData := model.Agent{
			Active:               true,
			PolicyID:             policyID,
			PolicyRevisionIdx:    policy.RevisionIdx, // FIXME the policy in fleet-server.yml does not match what's actually specified. maybe we need to use the policy that's retrived by the self monitor.
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
			return nil, fmt.Errorf("unable to enroll fleet-server: %w", err)
		}
		return &agentData, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to find agent entry: %w", err)
	} else {
		return &agent, nil
		// TODO santiy check agent that is found?
	}
}

func (f *Fleet) standAloneCheckin(agent *model.Agent, ct *api.CheckinT) runFunc {
	return func(ctx context.Context) error {
		tick := time.NewTimer(30 * time.Second) // fleet-server holds poll open for up to 5m
		defer tick.Stop()
		var ackToken string // TODO persistence?
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ts := <-tick.C:
				log.Info().Msg("self-checkin start")
				body := api.CheckinRequest{
					Status:   "HEALTHY", // TODO change to use reporter?
					AckToken: ackToken,
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
				log.Info().Msgf("self-checkin success token: %s, %d actions", ackToken, len(rBody.Actions))
				// TODO handle policy-change, unenroll, and settings actions? upgrade?
				log.Info().Msgf("self-checkin actions: %v", rBody.Actions)
				tick.Reset(30 * time.Second)
			}
		}
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
