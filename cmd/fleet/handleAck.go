// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/pkg/errors"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var ErrEventAgentIdMismatch = errors.New("event agentId mismatch")

type AckT struct {
	cfg   *config.Server
	limit *limit.Limiter
	bulk  bulk.Bulk
	cache cache.Cache
}

func NewAckT(cfg *config.Server, bulker bulk.Bulk, cache cache.Cache) *AckT {
	log.Info().
		Interface("limits", cfg.Limits.AckLimit).
		Msg("Setting config ack_limits")

	return &AckT{
		cfg:   cfg,
		bulk:  bulker,
		cache: cache,
		limit: limit.NewLimiter(&cfg.Limits.AckLimit),
	}
}

func (rt Router) handleAcks(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	id := ps.ByName("id")

	reqId := r.Header.Get(logger.HeaderRequestID)

	zlog := log.With().
		Str(LogAgentId, id).
		Str(EcsHttpRequestId, reqId).
		Logger()

	err := rt.ack.handleAcks(&zlog, w, r, id)

	if err != nil {
		cntAcks.IncError(err)
		resp := NewErrorResp(err)

		zlog.WithLevel(resp.Level).
			Err(err).
			Int(EcsHttpResponseCode, resp.StatusCode).
			Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
			Msg("fail ACK")

		if err := resp.Write(w); err != nil {
			zlog.Error().Err(err).Msg("fail writing error response")
		}
	}
}

func (ack *AckT) handleAcks(zlog *zerolog.Logger, w http.ResponseWriter, r *http.Request, id string) error {
	limitF, err := ack.limit.Acquire()
	if err != nil {
		return err
	}
	defer limitF()

	agent, err := authAgent(r, &id, ack.bulk, ack.cache)
	if err != nil {
		return err
	}

	// Pointer is passed in to allow UpdateContext by child function
	zlog.UpdateContext(func(ctx zerolog.Context) zerolog.Context {
		return ctx.Str(LogAccessApiKeyId, agent.AccessApiKeyId)
	})

	// Metrics; serenity now.
	dfunc := cntAcks.IncStart()
	defer dfunc()

	return ack.processRequest(*zlog, w, r, agent)
}

func (ack *AckT) processRequest(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, agent *model.Agent) error {

	body := r.Body

	// Limit the size of the body to prevent malicious agent from exhausting RAM in server
	if ack.cfg.Limits.AckLimit.MaxBody > 0 {
		body = http.MaxBytesReader(w, body, ack.cfg.Limits.AckLimit.MaxBody)
	}

	raw, err := ioutil.ReadAll(body)
	if err != nil {
		return errors.Wrap(err, "handleAcks read body")
	}

	cntAcks.bodyIn.Add(uint64(len(raw)))

	var req AckRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return errors.Wrap(err, "handleAcks unmarshal")
	}

	zlog.Trace().RawJSON("raw", raw).Msg("Ack request")

	zlog = zlog.With().Int("nEvents", len(req.Events)).Logger()

	if err = ack.handleAckEvents(r.Context(), zlog, agent, req.Events); err != nil {
		return err
	}

	resp := AckResponse{"acks"}

	data, err := json.Marshal(&resp)
	if err != nil {
		return errors.Wrap(err, "handleAcks marshal response")
	}

	var nWritten int
	if nWritten, err = w.Write(data); err != nil {
		return err
	}

	cntAcks.bodyOut.Add(uint64(nWritten))

	return nil
}

func (ack *AckT) handleAckEvents(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, events []Event) error {
	var policyAcks []string
	var unenroll bool
	for n, ev := range events {
		zlog.Info().
			Str("actionType", ev.Type).
			Str("actionSubType", ev.SubType).
			Str("actionId", ev.ActionId).
			Str("timestamp", ev.Timestamp).
			Int("n", n).
			Msg("ack event")

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
				return errors.Wrap(err, "find actions")
			}
			if len(actions) == 0 {
				return errors.New("no matching action")
			}
			action = actions[0]
			ack.cache.SetAction(action)
		}

		acr := model.ActionResult{
			ActionId:       ev.ActionId,
			AgentId:        agent.Id,
			StartedAt:      ev.StartedAt,
			CompletedAt:    ev.CompletedAt,
			ActionData:     ev.ActionData,
			ActionResponse: ev.ActionResponse,
			Data:           ev.Data,
			Error:          ev.Error,
		}
		if _, err := dl.CreateActionResult(ctx, ack.bulk, acr); err != nil {
			return errors.Wrap(err, "create action result")
		}

		if ev.Error == "" {
			if action.Type == TypeUnenroll {
				unenroll = true
			} else if action.Type == TypeUpgrade {
				if err := ack.handleUpgrade(ctx, zlog, agent); err != nil {
					return err
				}
			}
		}
	}

	if len(policyAcks) > 0 {
		if err := ack.handlePolicyChange(ctx, zlog, agent, policyAcks...); err != nil {
			return err
		}
	}

	if unenroll {
		if err := ack.handleUnenroll(ctx, zlog, agent); err != nil {
			return err
		}
	}

	return nil
}

func (ack *AckT) handlePolicyChange(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, actionIds ...string) error {
	// If more than one, pick the winner;
	// 0) Correct policy id
	// 1) Highest revision/coordinator number

	found := false
	currRev := agent.PolicyRevisionIdx
	currCoord := agent.PolicyCoordinatorIdx
	for _, a := range actionIds {
		rev, ok := policy.RevisionFromString(a)

		zlog.Debug().
			Str("agent.policyId", agent.PolicyId).
			Int64("agent.revisionIdx", currRev).
			Int64("agent.coordinatorIdx", currCoord).
			Str("rev.policyId", rev.PolicyId).
			Int64("rev.revisionIdx", rev.RevisionIdx).
			Int64("rev.coordinatorIdx", rev.CoordinatorIdx).
			Msg("ack policy revision")

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

	sz := len(agent.DefaultApiKeyHistory)
	if sz > 0 {
		ids := make([]string, sz)
		for i := 0; i < sz; i++ {
			ids[i] = agent.DefaultApiKeyHistory[i].Id
		}
		log.Info().Strs("ids", ids).Msg("Invalidate old API keys")
		if err := ack.bulk.ApiKeyInvalidate(ctx, ids...); err != nil {
			log.Info().Err(err).Strs("ids", ids).Msg("Failed to invalidate API keys")
		}
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

	zlog.Info().Err(err).
		Str(LogPolicyId, agent.PolicyId).
		Int64("policyRevision", currRev).
		Int64("policyCoordinator", currCoord).
		Msg("ack policy")

	return errors.Wrap(err, "handlePolicyChange update")
}

func (ack *AckT) handleUnenroll(ctx context.Context, zlog zerolog.Logger, agent *model.Agent) error {
	apiKeys := _getAPIKeyIDs(agent)
	if len(apiKeys) > 0 {
		zlog = zlog.With().Strs(LogApiKeyId, apiKeys).Logger()

		if err := ack.bulk.ApiKeyInvalidate(ctx, apiKeys...); err != nil {
			return errors.Wrap(err, "handleUnenroll invalidate apikey")
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
		return errors.Wrap(err, "handleUnenroll marshal")
	}

	if err = ack.bulk.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh()); err != nil {
		return errors.Wrap(err, "handleUnenroll update")
	}

	zlog.Info().Msg("ack unenroll")
	return nil
}

func (ack *AckT) handleUpgrade(ctx context.Context, zlog zerolog.Logger, agent *model.Agent) error {

	now := time.Now().UTC().Format(time.RFC3339)
	doc := bulk.UpdateFields{
		dl.FieldUpgradeStartedAt: nil,
		dl.FieldUpgradedAt:       now,
	}

	body, err := doc.Marshal()
	if err != nil {
		return errors.Wrap(err, "handleUpgrade marshal")
	}

	if err = ack.bulk.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh()); err != nil {
		return errors.Wrap(err, "handleUpgrade update")
	}

	zlog.Info().
		Str("lastReportedVersion", agent.Agent.Version).
		Str("upgradedAt", now).
		Msg("ack upgrade")

	return nil
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

const kUpdatePolicyPrefix = `{"script":{"lang":"painless","source":"if (ctx._source.policy_id == params.id) {ctx._source.remove('default_api_key_history');ctx._source.` +
	dl.FieldPolicyRevisionIdx +
	` = params.rev;ctx._source.` +
	dl.FieldPolicyCoordinatorIdx +
	`= params.coord;ctx._source.` +
	dl.FieldUpdatedAt +
	` = params.ts;} else {ctx.op = \"noop\";}","params": {"id":"`

func makeUpdatePolicyBody(policyId string, newRev, coordIdx int64) []byte {

	var buf bytes.Buffer
	buf.Grow(410)

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
