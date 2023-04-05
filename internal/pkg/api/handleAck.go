// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	"go.elastic.co/apm/module/apmhttp/v2"
	"go.elastic.co/apm/v2"
)

const (
	TypeUnenroll = "UNENROLL"
	TypeUpgrade  = "UPGRADE"
)

var (
	ErrUpdatingInactiveAgent = errors.New("updating inactive agent")
)

type HTTPError struct {
	Status int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d: %s", e.Status, http.StatusText(e.Status))
}

func NewAckResponse(size int) AckResponse {
	return AckResponse{
		Action: "acks",
		Errors: false,
		Items:  make([]AckResponseItem, size),
	}
}

func (a *AckResponse) setMessage(pos int, status int, message string) {
	if status != http.StatusOK {
		a.Errors = true
	}
	a.Items[pos].Status = status
	a.Items[pos].Message = &message
}

func (a *AckResponse) SetResult(pos int, status int) {
	a.setMessage(pos, status, http.StatusText(status))
}

func (a *AckResponse) SetError(pos int, err error) {
	var esErr *es.ErrElastic
	if errors.As(err, &esErr) {
		a.setMessage(pos, esErr.Status, esErr.Reason)
	} else {
		a.SetResult(pos, http.StatusInternalServerError)
	}
}

type AckT struct {
	cfg   *config.Server
	bulk  bulk.Bulk
	cache cache.Cache
}

func NewAckT(cfg *config.Server, bulker bulk.Bulk, cache cache.Cache) *AckT {
	return &AckT{
		cfg:   cfg,
		bulk:  bulker,
		cache: cache,
	}
}

func (ack *AckT) handleAcks(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, id string) error {
	agent, err := authAgent(r, &id, ack.bulk, ack.cache)
	if err != nil {
		return err
	}
	zlog = zlog.With().Str(LogAccessAPIKeyID, agent.AccessAPIKeyID).Logger()
	ctx := zlog.WithContext(r.Context())
	r = r.WithContext(ctx)

	return ack.processRequest(zlog, w, r, agent)
}

func (ack *AckT) processRequest(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, agent *model.Agent) error {
	body := r.Body

	// Limit the size of the body to prevent malicious agent from exhausting RAM in server
	if ack.cfg.Limits.AckLimit.MaxBody > 0 {
		body = http.MaxBytesReader(w, body, ack.cfg.Limits.AckLimit.MaxBody)
	}

	raw, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("handleAcks read body: %w", err)
	}

	cntAcks.bodyIn.Add(uint64(len(raw)))

	var req AckRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("handleAcks unmarshal: %w", err)
	}

	zlog.Trace().RawJSON("raw", raw).Msg("Ack request")

	zlog = zlog.With().Int("nEvents", len(req.Events)).Logger()

	resp, err := ack.handleAckEvents(r.Context(), zlog, agent, req.Events)
	if err != nil {
		var herr *HTTPError
		if errors.As(err, &herr) {
			w.WriteHeader(herr.Status)
		} else {
			// Non-HTTP error will be handled at higher level
			return err
		}
	}

	// Always write response body even if the error HTTP status code was set
	data, err := json.Marshal(&resp)
	if err != nil {
		return fmt.Errorf("handleAcks marshal response: %w", err)
	}

	var nWritten int
	if nWritten, err = w.Write(data); err != nil {
		return err
	}

	cntAcks.bodyOut.Add(uint64(nWritten))

	return nil
}

func eventToActionResult(agentID string, ev Event) (acr model.ActionResult) {
	return model.ActionResult{
		ActionID:        ev.ActionId,
		AgentID:         agentID,
		ActionInputType: ev.ActionInputType,
		StartedAt:       ev.StartedAt,
		CompletedAt:     ev.CompletedAt,
		ActionData:      fromPtr(ev.ActionData),
		ActionResponse:  fromPtr(ev.ActionResponse),
		Data:            fromPtr(ev.Data),
		Error:           fromPtr(ev.Error),
	}
}

// handleAckEvents can return:
// 1. AckResponse and nil error, when the whole request is successful
// 2. AckResponse and non-nil error, when the request items had errors
func (ack *AckT) handleAckEvents(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, events []Event) (AckResponse, error) {
	span, ctx := apm.StartSpan(ctx, "handleAckEvents", "ack")
	defer span.End()
	var policyAcks []string

	var policyIdxs []int
	var unenrollIdxs []int

	res := NewAckResponse(len(events))

	// Error collects the largest error HTTP Status code from all acked events
	httpErr := HTTPError{http.StatusOK}

	setResult := func(pos, status int) {
		if status > httpErr.Status {
			httpErr.Status = status
		}
		res.SetResult(pos, status)
	}

	setError := func(pos int, err error, span *apm.Span) {
		var esErr *es.ErrElastic
		if errors.As(err, &esErr) {
			setResult(pos, esErr.Status)
		} else {
			setResult(pos, http.StatusInternalServerError)
		}
		res.SetError(pos, err)
		e := apm.CaptureError(ctx, err)
		e.Send()
	}

	for n, ev := range events {
		log := zlog.With().
			Str("actionType", string(ev.Type)).
			Str("actionSubType", string(ev.Subtype)).
			Str("actionId", ev.ActionId).
			Str("agentId", ev.AgentId).
			Str("timestamp", ev.Timestamp).
			Int("n", n).Logger()

		log.Info().Msg("ack event")

		// Check agent id mismatch
		if ev.AgentId != "" && ev.AgentId != agent.Id {
			log.Error().Msg("agent id mismatch")
			setResult(n, http.StatusBadRequest)
			continue
		}

		// Check if this is the policy change ack
		// The policy change acks are handled after actions
		if strings.HasPrefix(ev.ActionId, "policy:") {
			if ev.Error == nil {
				// only added if no error on action
				policyAcks = append(policyAcks, ev.ActionId)
				policyIdxs = append(policyIdxs, n)
			}
			// Set OK status, this can be overwritten in case of the errors later when the policy change events acked
			setResult(n, http.StatusOK)
			continue
		}

		// Process non-policy change actions
		// Find matching action by action ID
		action, ok := ack.cache.GetAction(ev.ActionId)
		if !ok {
			// Find action by ID
			actions, err := dl.FindAction(ctx, ack.bulk, ev.ActionId)
			if err != nil {
				log.Error().Err(err).Msg("find action")
				setError(n, err, span)
				continue
			}

			// Set 404 if action is not found. The agent can retry it later.
			if len(actions) == 0 {
				log.Error().Msg("no matching action")
				setResult(n, http.StatusNotFound)
				continue
			}
			action = actions[0]
			ack.cache.SetAction(action)
		}

		if err := ack.handleActionResult(ctx, zlog, agent, action, ev); err != nil {
			setError(n, err, span)
		} else {
			setResult(n, http.StatusOK)
		}

		if ev.Error == nil && action.Type == TypeUnenroll {
			unenrollIdxs = append(unenrollIdxs, n)
		}
	}

	// Process policy acks
	if len(policyAcks) > 0 {
		if err := ack.handlePolicyChange(ctx, zlog, agent, policyAcks...); err != nil {
			for _, idx := range policyIdxs {
				setError(idx, err, span)
			}
		}
	}

	// Process unenroll acks
	if len(unenrollIdxs) > 0 {
		if err := ack.handleUnenroll(ctx, zlog, agent); err != nil {
			zlog.Error().Err(err).Msg("handle unenroll event")
			// Set errors for each unenroll event
			for _, idx := range unenrollIdxs {
				setError(idx, err, span)
			}
		}
	}

	// Return both the data and error code
	if httpErr.Status > http.StatusOK {
		return res, &httpErr
	}
	return res, nil
}

func (ack *AckT) handleActionResult(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, action model.Action, ev Event) error {
	// Build span links for actions
	var links []apm.SpanLink
	if action.Traceparent != "" {
		traceCtx, err := apmhttp.ParseTraceparentHeader(action.Traceparent)
		if err != nil {
			zlog.Trace().Err(err).Msgf("Error parsing traceparent: %s %s", action.Traceparent, err)
		} else {
			links = []apm.SpanLink{
				{
					Trace: traceCtx.Trace,
					Span:  traceCtx.Span,
				},
			}
		}
	}

	span, ctx := apm.StartSpanOptions(ctx, fmt.Sprintf("Process action result %s", action.Type), "app", apm.SpanOptions{Links: links})
	span.Context.SetLabel("action_id", action.Id)
	span.Context.SetLabel("agent_id", agent.Agent.ID)
	defer span.End()

	// Convert ack event to action result document
	acr := eventToActionResult(agent.Id, ev)

	// Save action result document
	if _, err := dl.CreateActionResult(ctx, ack.bulk, acr); err != nil {
		zlog.Error().Err(err).Msg("create action result")
		return err
	}

	if action.Type == TypeUpgrade {
		if err := ack.handleUpgrade(ctx, zlog, agent, ev); err != nil {
			zlog.Error().Err(err).Msg("handle upgrade event")
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
			Str("agent.policyId", agent.PolicyID).
			Int64("agent.revisionIdx", currRev).
			Int64("agent.coordinatorIdx", currCoord).
			Str("rev.policyId", rev.PolicyID).
			Int64("rev.revisionIdx", rev.RevisionIdx).
			Int64("rev.coordinatorIdx", rev.CoordinatorIdx).
			Msg("ack policy revision")

		if ok && rev.PolicyID == agent.PolicyID &&
			(rev.RevisionIdx > currRev ||
				(rev.RevisionIdx == currRev && rev.CoordinatorIdx > currCoord)) {
			found = true
			currRev = rev.RevisionIdx
			currCoord = rev.CoordinatorIdx
		}
	}

	if !found {
		return nil
	}

	for _, output := range agent.Outputs {
		if output.Type != policy.OutputTypeElasticsearch {
			continue
		}

		err := ack.updateAPIKey(ctx,
			zlog,
			agent.Id,
			output.APIKeyID, output.PermissionsHash, output.ToRetireAPIKeyIds)
		if err != nil {
			return err
		}
	}

	err := ack.updateAgentDoc(ctx, zlog,
		agent.Id,
		currRev, currCoord,
		agent.PolicyID)
	if err != nil {
		return err
	}

	return nil
}

func (ack *AckT) updateAPIKey(ctx context.Context,
	zlog zerolog.Logger,
	agentID string,
	apiKeyID, permissionHash string,
	toRetireAPIKeyIDs []model.ToRetireAPIKeyIdsItems) error {

	if apiKeyID != "" {
		res, err := ack.bulk.APIKeyRead(ctx, apiKeyID, true)
		if err != nil {
			if isAgentActive(ctx, zlog, ack.bulk, agentID) {
				zlog.Error().
					Err(err).
					Str(LogAPIKeyID, apiKeyID).
					Msg("Failed to read API Key roles")
			} else {
				// race when API key was invalidated before acking
				zlog.Info().
					Err(err).
					Str(LogAPIKeyID, apiKeyID).
					Msg("Failed to read invalidated API Key roles")

				// prevents future checks
				return ErrUpdatingInactiveAgent
			}
		} else {
			clean, removedRolesCount, err := cleanRoles(res.RoleDescriptors)
			if err != nil {
				zlog.Error().
					Err(err).
					RawJSON("roles", res.RoleDescriptors).
					Str(LogAPIKeyID, apiKeyID).
					Msg("Failed to cleanup roles")
			} else if removedRolesCount > 0 {
				if err := ack.bulk.APIKeyUpdate(ctx, apiKeyID, permissionHash, clean); err != nil {
					zlog.Error().Err(err).RawJSON("roles", clean).Str(LogAPIKeyID, apiKeyID).Msg("Failed to update API Key")
				} else {
					zlog.Debug().
						Str("hash.sha256", permissionHash).
						Str(LogAPIKeyID, apiKeyID).
						RawJSON("roles", clean).
						Int("removedRoles", removedRolesCount).
						Msg("Updating agent record to pick up reduced roles.")
				}
			}
		}
		ack.invalidateAPIKeys(ctx, zlog, toRetireAPIKeyIDs, apiKeyID)
	}

	return nil
}

func (ack *AckT) updateAgentDoc(ctx context.Context,
	zlog zerolog.Logger,
	agentID string,
	currRev, currCoord int64,
	policyID string,
) error {
	body := makeUpdatePolicyBody(
		policyID,
		currRev,
		currCoord,
	)

	err := ack.bulk.Update(
		ctx,
		dl.FleetAgents,
		agentID,
		body,
		bulk.WithRefresh(),
		bulk.WithRetryOnConflict(3),
	)

	zlog.Err(err).
		Str(LogPolicyID, policyID).
		Int64("policyRevision", currRev).
		Int64("policyCoordinator", currCoord).
		Msg("ack policy")

	if err != nil {
		return fmt.Errorf("handlePolicyChange update: %w", err)
	}
	return nil
}

func cleanRoles(roles json.RawMessage) (json.RawMessage, int, error) {
	rr := smap.Map{}
	if err := json.Unmarshal(roles, &rr); err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal provided roles: %w", err)
	}

	keys := make([]string, 0, len(rr))
	for k := range rr {
		if strings.HasSuffix(k, "-rdstale") {
			keys = append(keys, k)
		}
	}

	if len(keys) == 0 {
		return roles, 0, nil
	}

	for _, k := range keys {
		delete(rr, k)
	}

	r, err := json.Marshal(rr)
	if err != nil {
		return r, len(keys), fmt.Errorf("failed to marshal resulting role definition: %w", err)
	}
	return r, len(keys), nil
}

func (ack *AckT) invalidateAPIKeys(ctx context.Context, zlog zerolog.Logger, toRetireAPIKeyIDs []model.ToRetireAPIKeyIdsItems, skip string) {
	ids := make([]string, 0, len(toRetireAPIKeyIDs))
	for _, k := range toRetireAPIKeyIDs {
		if k.ID == skip || k.ID == "" {
			continue
		}
		ids = append(ids, k.ID)
	}

	if len(ids) > 0 {
		zlog.Info().Strs("fleet.policy.apiKeyIDsToRetire", ids).Msg("Invalidate old API keys")
		if err := ack.bulk.APIKeyInvalidate(ctx, ids...); err != nil {
			zlog.Info().Err(err).Strs("ids", ids).Msg("Failed to invalidate API keys")
		}
	}
}

func (ack *AckT) handleUnenroll(ctx context.Context, zlog zerolog.Logger, agent *model.Agent) error {
	apiKeys := agent.APIKeyIDs()
	if len(apiKeys) > 0 {
		zlog = zlog.With().Strs(LogAPIKeyID, apiKeys).Logger()

		if err := ack.bulk.APIKeyInvalidate(ctx, apiKeys...); err != nil {
			return fmt.Errorf("handleUnenroll invalidate apikey: %w", err)
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
		return fmt.Errorf("handleUnenroll marshal: %w", err)
	}

	if err = ack.bulk.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
		return fmt.Errorf("handleUnenroll update: %w", err)
	}

	zlog.Info().Msg("ack unenroll")
	return nil
}

func (ack *AckT) handleUpgrade(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, event Event) error {
	now := time.Now().UTC().Format(time.RFC3339)
	doc := bulk.UpdateFields{}
	if event.Error != nil {
		// unmarshal event payload
		var pl struct {
			Retry   bool `json:"retry"`
			Attempt int  `json:"retry_attempt"`
		}
		err := json.Unmarshal(fromPtr(event.Payload), &pl)
		if err != nil {
			zlog.Error().Err(err).Msg("unable to unmarshal upgrade event payload")
		}

		// if the payload indicates a retry, mark change the upgrade status to retrying.
		if pl.Retry {
			zlog.Info().Int("retry_attempt", pl.Attempt).Msg("marking agent upgrade as retrying")
			doc[dl.FieldUpgradeStatus] = "retrying" // Keep FieldUpgradeStatedAt abd FieldUpgradeded at to original values
		} else {
			zlog.Info().Int("retry_attempt", pl.Attempt).Msg("marking agent upgrade as failed, agent logs contain failure message")
			doc = bulk.UpdateFields{
				dl.FieldUpgradeStartedAt: nil,
				dl.FieldUpgradeStatus:    "failed",
			}
		}
	} else {
		doc = bulk.UpdateFields{
			dl.FieldUpgradeStartedAt: nil,
			dl.FieldUpgradeStatus:    nil,
			dl.FieldUpgradedAt:       now,
		}
	}

	body, err := doc.Marshal()
	if err != nil {
		return fmt.Errorf("handleUpgrade marshal: %w", err)
	}

	if err = ack.bulk.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
		return fmt.Errorf("handleUpgrade update: %w", err)
	}

	zlog.Info().
		Str("lastReportedVersion", agent.Agent.Version).
		Str("upgradedAt", now).
		Msg("ack upgrade")

	return nil
}

func isAgentActive(ctx context.Context, zlog zerolog.Logger, bulk bulk.Bulk, agentID string) bool {
	agent, err := dl.FindAgent(ctx, bulk, dl.QueryAgentByID, dl.FieldID, agentID)
	if err != nil {
		zlog.Error().
			Err(err).
			Msg("failed to find agent by ID")
		return true
	}

	return agent.Active // it is a valid error in case agent is active (was not invalidated)
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

func makeUpdatePolicyBody(policyID string, newRev, coordIdx int64) []byte {

	var buf bytes.Buffer
	buf.Grow(410)

	//  Not pretty, but fast.
	buf.WriteString(kUpdatePolicyPrefix)
	buf.WriteString(policyID)
	buf.WriteString(`","rev":`)
	buf.WriteString(strconv.FormatInt(newRev, 10))
	buf.WriteString(`,"coord":`)
	buf.WriteString(strconv.FormatInt(coordIdx, 10))
	buf.WriteString(`,"ts":"`)
	buf.WriteString(time.Now().UTC().Format(time.RFC3339))
	buf.WriteString(`"}}}`)

	return buf.Bytes()
}
