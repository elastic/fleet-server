// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fleet/internal/pkg/policy"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/model"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

var ErrEventAgentIdMismatch = errors.New("event agentId mismatch")

func (rt Router) handleAcks(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")

	err := _handleAcks(w, r, id, rt.ct.bulker)

	if err != nil {
		code := http.StatusBadRequest
		// Don't log connection drops
		if err != context.Canceled {
			log.Error().Err(err).Int("code", code).Msg("Fail ACK")
		}

		http.Error(w, err.Error(), code)
	}
}

// TODO: Handle UPGRADE and UNENROLL
func _handleAcks(w http.ResponseWriter, r *http.Request, id string, bulker bulk.Bulk) error {
	agent, err := authAgent(r, id, bulker)
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

	if err = _handleAckEvents(r.Context(), agent, req.Events, bulker); err != nil {
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

func _handleAckEvents(ctx context.Context, agent *model.Agent, events []Event, bulker bulk.Bulk) error {
	var policyAcks []string
	for _, ev := range events {
		if ev.AgentId != "" && ev.AgentId != agent.Id {
			return ErrEventAgentIdMismatch
		}
		if strings.HasPrefix(ev.ActionId, "policy:") {
			policyAcks = append(policyAcks, ev.ActionId)
			continue
		}

		acr := model.ActionResult{
			ActionId: ev.ActionId,
			AgentId:  agent.Id,
			Data:     ev.Data,
			Error:    ev.Error,
		}
		if _, err := dl.CreateActionResult(ctx, bulker, acr); err != nil {
			return err
		}
	}

	if len(policyAcks) > 0 {
		if err := _handlePolicyChange(ctx, bulker, agent, policyAcks...); err != nil {
			return err
		}
	}

	// TODO: handle UPGRADE and UNENROLL

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
