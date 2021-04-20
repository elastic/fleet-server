// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

var ErrEventAgentIdMismatch = errors.New("event agentId mismatch")

type AckT struct {
	limit *limit.Limiter
	bulk  bulk.Bulk
	cache cache.Cache
}

func NewAckT(cfg *config.Server, bulker bulk.Bulk, cache cache.Cache) *AckT {
	log.Info().
		Interface("limits", cfg.Limits.AckLimit).
		Msg("Ack install limits")

	return &AckT{
		bulk:  bulker,
		cache: cache,
		limit: limit.NewLimiter(&cfg.Limits.AckLimit),
	}
}

func (rt Router) handleAcks(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")

	err := rt.ack.handleAcks(w, r, id)

	if err != nil {
		code, lvl := cntAcks.IncError(err)

		log.WithLevel(lvl).
			Err(err).
			Int("code", code).
			Msg("Fail ACK")

		http.Error(w, "", code)
	}
}

func (ack AckT) handleAcks(w http.ResponseWriter, r *http.Request, id string) error {
	limitF, err := ack.limit.Acquire()
	if err != nil {
		return err
	}
	defer limitF()

	agent, err := authAgent(r, id, ack.bulk, ack.cache)
	if err != nil {
		return err
	}

	// Metrics; serenity now.
	dfunc := cntAcks.IncStart()
	defer dfunc()

	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	cntAcks.bodyIn.Add(uint64(len(raw)))

	var req AckRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return err
	}

	log.Trace().RawJSON("raw", raw).Msg("Ack request")

	if err = ack.handleAckEvents(r.Context(), agent, req.Events); err != nil {
		return err
	}

	resp := AckResponse{"acks"}

	data, err := json.Marshal(&resp)
	if err != nil {
		return err
	}

	var nWritten int
	if nWritten, err = w.Write(data); err != nil {
		return err
	}

	cntAcks.bodyOut.Add(uint64(nWritten))

	return nil
}

func (ack *AckT) handleAckEvents(ctx context.Context, agent *model.Agent, events []Event) error {
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

		action, ok := ack.cache.GetAction(ev.ActionId)
		if !ok {
			actions, err := dl.FindAction(ctx, ack.bulk, ev.ActionId)
			if err != nil {
				return err
			}
			if len(actions) == 0 {
				return errors.New("no matching action")
			}
			action = actions[0]
			ack.cache.SetAction(action, time.Minute)
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
		if _, err := dl.CreateActionResult(ctx, ack.bulk, acr); err != nil {
			return err
		}

		if ev.Error == "" {
			if action.Type == TypeUnenroll {
				unenroll = true
			} else if action.Type == TypeUpgrade {
				if err := ack.handleUpgrade(ctx, agent); err != nil {
					return err
				}
			}
		}
	}

	if len(policyAcks) > 0 {
		if err := ack.handlePolicyChange(ctx, agent, policyAcks...); err != nil {
			return err
		}
	}

	if unenroll {
		if err := ack.handleUnenroll(ctx, agent); err != nil {
			return err
		}
	}

	return nil
}

func (ack *AckT) handlePolicyChange(ctx context.Context, agent *model.Agent, actionIds ...string) error {
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

	if !found {
		return nil
	}

	body := makeUpdatePolicyBody(
		agent.PolicyId,
		currRev,
		currCoord,
	)

	err := ack.bulk.Update(
		ctx,
		dl.FleetAgents,
		agent.Id,
		body,
		bulk.WithRefresh(),
		bulk.WithRetryOnConflict(3),
	)

	return err
}

func (ack *AckT) handleUnenroll(ctx context.Context, agent *model.Agent) error {
	apiKeys := _getAPIKeyIDs(agent)
	if len(apiKeys) > 0 {
		if err := apikey.Invalidate(ctx, ack.bulk.Client(), apiKeys...); err != nil {
			return err
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	doc := bulk.UpdateFields{
		dl.FieldActive:       false,
		dl.FieldUnenrolledAt: now,
		dl.FieldUpdatedAt:    now,
	}

	body, err := doc.Marshal()
	if err != nil {
		return err
	}

	return ack.bulk.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh())
}

func (ack *AckT) handleUpgrade(ctx context.Context, agent *model.Agent) error {

	now := time.Now().UTC().Format(time.RFC3339)
	doc := bulk.UpdateFields{
		dl.FieldUpgradeStartedAt: nil,
		dl.FieldUpgradedAt:       now,
	}

	body, err := doc.Marshal()
	if err != nil {
		return err
	}

	return ack.bulk.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh())
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

// Generate an update script that validates that the policy_id
// has not changed underneath us by an upstream process (Kibana or otherwise).
// We have a race condition where a user could have assigned a new policy to
// an agent while we were busy updating the old one.  A blind update to the
// agent record without a check could set the revision and coordIdx for the wrong
// policy.  This script should be coupled with a "retry_on_conflict" parameter
// to allow for *other* changes to the agent record while we running the script.
// (For example, say the background bulk check-in timestamp update task fires)
//
// WARNING: This assumes the input data is sanitized.

const kUpdatePolicyPrefix = `{"script":{"lang":"painless","source":"if (ctx._source.policy_id == params.id) {ctx._source.` +
	dl.FieldPolicyRevisionIdx +
	` = params.rev;ctx._source.` +
	dl.FieldPolicyCoordinatorIdx +
	`= params.coord;ctx._source.` +
	dl.FieldUpdatedAt +
	` = params.ts;} else {ctx.op = \"noop\";}","params": {"id":"`

func makeUpdatePolicyBody(policyId string, newRev, coordIdx int64) []byte {

	var buf bytes.Buffer
	buf.Grow(384)

	//  Not pretty, but fast.
	buf.WriteString(kUpdatePolicyPrefix)
	buf.WriteString(policyId)
	buf.WriteString(`","rev":`)
	buf.WriteString(strconv.FormatInt(newRev, 10))
	buf.WriteString(`,"coord":`)
	buf.WriteString(strconv.FormatInt(coordIdx, 10))
	buf.WriteString(`,"ts":"`)
	buf.WriteString(time.Now().UTC().Format(time.RFC3339))
	buf.WriteString(`"}}}`)

	return buf.Bytes()
}
