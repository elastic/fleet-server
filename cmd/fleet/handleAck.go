// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

var ErrEventAgentIdMismatch = errors.New("event agentId mismatch")

func (rt Router) handleAcks(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")

	err := _handleAcks(w, r, id, rt.ct.bulker, rt.ct.cache)

	if err != nil {
		code := http.StatusBadRequest
		// Don't log connection drops
		if err != context.Canceled {
			log.Error().Err(err).Int("code", code).Msg("Fail ACK")
		}

		http.Error(w, err.Error(), code)
	}
}

// TODO: Handle UPGRADE
func _handleAcks(w http.ResponseWriter, r *http.Request, id string, bulker bulk.Bulk, c cache.Cache) error {
	agent, err := authAgent(r, id, bulker, c)
	if err != nil {
		return err
	}

	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	var req AckRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return err
	}

	log.Trace().RawJSON("raw", raw).Msg("Ack request")

	if err = _handleAckEvents(r.Context(), agent, req.Events, bulker, c); err != nil {
		return err
	}

	// TODO: flesh this out
	resp := AckResponse{"acks"}

	data, err := json.Marshal(&resp)
	if err != nil {
		return err
	}

	if _, err = w.Write(data); err != nil {
		return err
	}

	return nil
}

func _handleAckEvents(ctx context.Context, agent *model.Agent, events []Event, bulker bulk.Bulk, c cache.Cache) error {
	var policyAcks []string
	var unenroll bool
	for _, ev := range events {
		if ev.AgentId != "" && ev.AgentId != agent.Id {
			return ErrEventAgentIdMismatch
		}
		if strings.HasPrefix(ev.ActionId, "policy:") {
			if ev.Error == "" {
				// only added if no error on action
				policyAcks = append(policyAcks, ev.ActionId)
			}
			continue
		}

		action, ok := c.GetAction(ev.ActionId)
		if !ok {
			actions, err := dl.FindAction(ctx, bulker, ev.ActionId)
			if err != nil {
				return err
			}
			if len(actions) == 0 {
				return errors.New("no matching action")
			}
			action = actions[0]
			c.SetAction(action)
		}

		acr := model.ActionResult{
			ActionId:    ev.ActionId,
			AgentId:     agent.Id,
			StartedAt:   ev.StartedAt,
			CompletedAt: ev.CompletedAt,
			ActionData:  ev.ActionData,
			Data:        ev.Data,
			Error:       ev.Error,
		}
		if _, err := dl.CreateActionResult(ctx, bulker, acr); err != nil {
			return err
		}

		if ev.Error == "" && action.Type == TypeUnenroll {
			unenroll = true
		}
	}

	if len(policyAcks) > 0 {
		if err := _handlePolicyChange(ctx, bulker, agent, policyAcks...); err != nil {
			return err
		}
	}

	if unenroll {
		if err := _handleUnenroll(ctx, bulker, agent); err != nil {
			return err
		}
	}

	// TODO: handle UPGRADE

	return nil
}

func _handlePolicyChange(ctx context.Context, bulker bulk.Bulk, agent *model.Agent, actionIds ...string) error {
	// If more than one, pick the winner;
	// 0) Correct policy id
	// 1) Highest revision/coordinator number

	found := false
	currRev := agent.PolicyRevisionIdx
	currCoord := agent.PolicyCoordinatorIdx
	for _, a := range actionIds {
		rev, ok := policy.RevisionFromString(a)
		if ok && rev.PolicyId == agent.PolicyId && (rev.RevisionIdx > currRev ||
			(rev.RevisionIdx == currRev && rev.CoordinatorIdx > currCoord)) {
			found = true
			currRev = rev.RevisionIdx
			currCoord = rev.CoordinatorIdx
		}
	}

	if found {
		updates := make([]bulk.BulkOp, 0, 1)
		fields := map[string]interface{}{
			dl.FieldPolicyRevisionIdx:    currRev,
			dl.FieldPolicyCoordinatorIdx: currCoord,
		}
		fields[dl.FieldUpdatedAt] = time.Now().UTC().Format(time.RFC3339)

		source, err := json.Marshal(map[string]interface{}{
			"doc": fields,
		})
		if err != nil {
			return err
		}

		updates = append(updates, bulk.BulkOp{
			Id:    agent.Id,
			Body:  source,
			Index: dl.FleetAgents,
		})

		err = bulker.MUpdate(ctx, updates, bulk.WithRefresh())
		if err != nil {
			return err
		}
	}

	return nil
}

func _handleUnenroll(ctx context.Context, bulker bulk.Bulk, agent *model.Agent) error {
	apiKeys := _getAPIKeyIDs(agent)
	if len(apiKeys) > 0 {
		if err := apikey.Invalidate(ctx, bulker.Client(), apiKeys...); err != nil {
			return err
		}
	}

	updates := make([]bulk.BulkOp, 0, 1)
	now := time.Now().UTC().Format(time.RFC3339)
	fields := map[string]interface{}{
		dl.FieldActive:       false,
		dl.FieldUnenrolledAt: now,
		dl.FieldUpdatedAt:    now,
	}

	source, err := json.Marshal(map[string]interface{}{
		"doc": fields,
	})
	if err != nil {
		return err
	}

	updates = append(updates, bulk.BulkOp{
		Id:    agent.Id,
		Body:  source,
		Index: dl.FleetAgents,
	})

	return bulker.MUpdate(ctx, updates, bulk.WithRefresh())
}

func _getAPIKeyIDs(agent *model.Agent) []string {
	keys := make([]string, 0, 1)
	if agent.AccessApiKeyId != "" {
		keys = append(keys, agent.AccessApiKeyId)
	}
	if agent.DefaultApiKeyId != "" {
		keys = append(keys, agent.DefaultApiKeyId)
	}
	return keys
}
