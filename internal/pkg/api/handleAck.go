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
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miolini/datacounter"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/module/apmhttp/v2"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
)

const (
	TypeUnenroll = "UNENROLL"
	TypeUpgrade  = "UPGRADE"
	TypeMigrate  = "MIGRATE"
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
	req, err := ack.validateRequest(zlog, w, r)
	if err != nil {
		return err
	}

	zlog = zlog.With().Int("nEvents", len(req.Events)).Logger()

	resp, err := ack.handleAckEvents(r.Context(), zlog, agent, req.Events)
	span, _ := apm.StartSpan(r.Context(), "response", "write")
	defer span.End()
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

	cntAcks.bodyOut.Add(uint64(nWritten)) //nolint:gosec // disable G115

	return nil
}

func (ack *AckT) validateRequest(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request) (*AckRequest, error) {
	span, _ := apm.StartSpan(r.Context(), "validateRequest", "validate")
	defer span.End()

	body := r.Body

	// Limit the size of the body to prevent malicious agent from exhausting RAM in server
	if ack.cfg.Limits.AckLimit.MaxBody > 0 {
		body = http.MaxBytesReader(w, body, ack.cfg.Limits.AckLimit.MaxBody)
	}
	readCounter := datacounter.NewReaderCounter(body)

	var req AckRequest
	dec := json.NewDecoder(readCounter)
	if err := dec.Decode(&req); err != nil {
		return nil, &BadRequestErr{msg: "unable to decode ack request", nextErr: err}
	}

	cntAcks.bodyIn.Add(readCounter.Count())
	zlog.Trace().Msg("Ack request")
	return &req, nil
}

func eventToActionResult(agentID, aType string, namespaces []string, ev AckRequest_Events_Item) (acr model.ActionResult) {
	switch aType {
	case string(REQUESTDIAGNOSTICS):
		event, _ := ev.AsDiagnosticsEvent()
		p, _ := json.Marshal(event.Data)
		return model.ActionResult{
			ActionID:   event.ActionId,
			AgentID:    agentID,
			Namespaces: namespaces,
			Data:       p,
			Error:      fromPtr(event.Error),
			Timestamp:  event.Timestamp.Format(time.RFC3339Nano),
		}
	case string(INPUTACTION):
		event, _ := ev.AsInputEvent()
		return model.ActionResult{
			ActionID:        event.ActionId,
			AgentID:         agentID,
			Namespaces:      namespaces,
			ActionInputType: event.ActionInputType,
			StartedAt:       event.StartedAt.Format(time.RFC3339Nano),
			CompletedAt:     event.CompletedAt.Format(time.RFC3339Nano),
			ActionData:      event.ActionData,
			ActionResponse:  event.ActionResponse,
			Error:           fromPtr(event.Error),
			Timestamp:       event.Timestamp.Format(time.RFC3339Nano),
		}
	default: // UPGRADE action acks are also handled by handelUpgrade (deprecated func)
		event, _ := ev.AsGenericEvent()
		return model.ActionResult{
			ActionID:   event.ActionId,
			Namespaces: namespaces,
			AgentID:    agentID,
			Error:      fromPtr(event.Error),
			Timestamp:  event.Timestamp.Format(time.RFC3339Nano),
		}
	}
}

// handleAckEvents can return:
// 1. AckResponse and nil error, when the whole request is successful
// 2. AckResponse and non-nil error, when the request items had errors
func (ack *AckT) handleAckEvents(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, events []AckRequest_Events_Item) (AckResponse, error) {
	span, ctx := apm.StartSpan(ctx, "handleAckEvents", "process")
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

	setError := func(pos int, err error) {
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
		event, _ := ev.AsGenericEvent()
		span, ctx := apm.StartSpan(ctx, "ackEvent", "process")
		span.Context.SetLabel("agent_id", agent.Agent.ID)
		span.Context.SetLabel("action_id", event.ActionId)
		log := zlog.With().
			Str(ecs.ActionID, event.ActionId).
			Str(ecs.AgentID, event.AgentId).
			Time("timestamp", event.Timestamp).
			Int("n", n).Logger()
		log.Info().Msg("ack event")

		// Check agent id mismatch
		if event.AgentId != "" && event.AgentId != agent.Id {
			log.Error().Msg("agent id mismatch")
			setResult(n, http.StatusBadRequest)
			span.End()
			continue
		}

		// Check if this is the policy change ack
		// The policy change acks are handled after actions
		if strings.HasPrefix(event.ActionId, "policy:") {
			if event.Error == nil {
				// only added if no error on action
				policyAcks = append(policyAcks, event.ActionId)
				policyIdxs = append(policyIdxs, n)
			}
			// Set OK status, this can be overwritten in case of the errors later when the policy change events acked
			setResult(n, http.StatusOK)
			span.End()
			continue
		}

		// Process non-policy change actions
		// Find matching action by action ID
		vSpan, vCtx := apm.StartSpan(ctx, "ackAction", "validate")
		action, ok := ack.cache.GetAction(event.ActionId)
		if !ok {
			// Find action by ID
			actions, err := dl.FindAction(vCtx, ack.bulk, event.ActionId)
			if err != nil {
				log.Error().Err(err).Msg("find action")
				setError(n, err)
				vSpan.End()
				span.End()
				continue
			}

			// Set 404 if action is not found. The agent can retry it later.
			if len(actions) == 0 {
				log.Error().Msg("no matching action")
				setResult(n, http.StatusNotFound)
				vSpan.End()
				span.End()
				continue
			}
			action = actions[0]
			ack.cache.SetAction(action)
		}
		vSpan.End()

		if err := ack.handleActionResult(ctx, zlog, agent, action, ev); err != nil {
			setError(n, err)
		} else {
			setResult(n, http.StatusOK)
		}

		if event.Error == nil && (action.Type == TypeUnenroll || action.Type == TypeMigrate) {
			unenrollIdxs = append(unenrollIdxs, n)
		}
		span.End()
	}

	// Process policy acks
	if len(policyAcks) > 0 {
		if err := ack.handlePolicyChange(ctx, zlog, agent, policyAcks...); err != nil {
			for _, idx := range policyIdxs {
				setError(idx, err)
			}
		}
	}

	// Process unenroll acks
	if len(unenrollIdxs) > 0 {
		if err := ack.handleUnenroll(ctx, zlog, agent); err != nil {
			zlog.Error().Err(err).Msg("handle unenroll event")
			// Set errors for each unenroll event
			for _, idx := range unenrollIdxs {
				setError(idx, err)
			}
		}
	}

	// Return both the data and error code
	if httpErr.Status > http.StatusOK {
		return res, &httpErr
	}
	return res, nil
}

func (ack *AckT) handleActionResult(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, action model.Action, ev AckRequest_Events_Item) error {
	// Build span links for actions
	var links []apm.SpanLink
	if ack.bulk.HasTracer() && action.Traceparent != "" {
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

	span, ctx := apm.StartSpanOptions(ctx, fmt.Sprintf("Process action result %s", action.Type), "process", apm.SpanOptions{Links: links})
	span.Context.SetLabel("action_id", action.Id)
	span.Context.SetLabel("agent_id", agent.Agent.ID)
	defer span.End()

	// Convert ack event to action result document
	acr := eventToActionResult(agent.Id, action.Type, action.Namespaces, ev)

	// Save action result document
	if err := dl.CreateActionResult(ctx, ack.bulk, acr); err != nil {
		zlog.Error().Err(err).Str(ecs.AgentID, agent.Agent.ID).Str(ecs.ActionID, action.Id).Msg("create action result")
		return err
	}

	if action.Type == TypeUpgrade {
		event, _ := ev.AsUpgradeEvent()
		if err := ack.handleUpgrade(ctx, zlog, agent, event); err != nil {
			zlog.Error().Err(err).Str(ecs.AgentID, agent.Agent.ID).Str(ecs.ActionID, action.Id).Msg("handle upgrade event")
			return err
		}
	}

	return nil
}

func (ack *AckT) handlePolicyChange(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, actionIds ...string) error {
	span, ctx := apm.StartSpan(ctx, "ackPolicyChanges", "process")
	defer span.End()
	// If more than one, pick the winner;
	// 0) Correct policy id
	// 1) Highest revision number

	found := false
	currRev := agent.PolicyRevisionIdx
	vSpan, _ := apm.StartSpan(ctx, "checkPolicyActions", "validate")
	for _, a := range actionIds {
		rev, ok := policy.RevisionFromString(a)

		zlog.Debug().
			Str("agent.policyId", agent.PolicyID).
			Int64("agent.revisionIdx", currRev).
			Str("rev.policyId", rev.PolicyID).
			Int64(ecs.RevisionIdx, rev.RevisionIdx).
			Msg("ack policy revision")

		if ok && rev.PolicyID == agent.PolicyID && rev.RevisionIdx > currRev {
			found = true
			currRev = rev.RevisionIdx
		}
	}

	vSpan.End()
	if !found {
		return nil
	}

	for outputName, output := range agent.Outputs {
		if output.Type != policy.OutputTypeElasticsearch {
			continue
		}

		err := ack.updateAPIKey(ctx,
			zlog,
			agent.Id,
			output.APIKeyID, output.PermissionsHash, output.ToRetireAPIKeyIds, outputName)
		if err != nil {
			return err
		}
	}

	err := ack.updateAgentDoc(ctx, zlog,
		agent.Id,
		currRev,
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
	toRetireAPIKeyIDs []model.ToRetireAPIKeyIdsItems, outputName string) error {
	return updateAPIKey(ctx, zlog, ack.bulk, agentID, apiKeyID, permissionHash, toRetireAPIKeyIDs, outputName)
}

func updateAPIKey(ctx context.Context,
	zlog zerolog.Logger,
	bulk bulk.Bulk,
	agentID string,
	apiKeyID, permissionHash string,
	toRetireAPIKeyIDs []model.ToRetireAPIKeyIdsItems, outputName string) error {
	// use output bulker if exists
	outBulk := bulk
	if outputName != "" {
		outputBulk := bulk.GetBulker(outputName)
		if outputBulk != nil {
			zlog.Debug().Str(ecs.PolicyOutputName, outputName).Msg("Using output bulker in updateAPIKey")
			outBulk = outputBulk
		}
	}
	if apiKeyID != "" {
		res, err := outBulk.APIKeyRead(ctx, apiKeyID, true)
		if err != nil {
			if isAgentActive(ctx, zlog, outBulk, agentID) {
				zlog.Warn().
					Err(err).
					Str(LogAPIKeyID, apiKeyID).
					Str(ecs.PolicyOutputName, outputName).
					Msg("Failed to read API Key roles")
			} else {
				// race when API key was invalidated before acking
				zlog.Info().
					Err(err).
					Str(LogAPIKeyID, apiKeyID).
					Str(ecs.PolicyOutputName, outputName).
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
				if err := outBulk.APIKeyUpdate(ctx, apiKeyID, permissionHash, clean); err != nil {
					zlog.Error().Err(err).RawJSON("roles", clean).Str(LogAPIKeyID, apiKeyID).Str(ecs.PolicyOutputName, outputName).Msg("Failed to update API Key")
				} else {
					zlog.Debug().
						Str("hash.sha256", permissionHash).
						Str(LogAPIKeyID, apiKeyID).
						RawJSON("roles", clean).
						Int("removedRoles", removedRolesCount).
						Str(ecs.PolicyOutputName, outputName).
						Msg("Updating agent record to pick up reduced roles.")
				}
			}
		}
		invalidateAPIKeys(ctx, zlog, bulk, toRetireAPIKeyIDs, apiKeyID)
	}

	return nil
}

func (ack *AckT) updateAgentDoc(ctx context.Context,
	zlog zerolog.Logger,
	agentID string,
	currRev int64,
	policyID string,
) error {
	span, ctx := apm.StartSpan(ctx, "updateAgentDoc", "update")
	defer span.End()
	body := makeUpdatePolicyBody(
		policyID,
		currRev,
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
	invalidateAPIKeys(ctx, zlog, ack.bulk, toRetireAPIKeyIDs, skip)
}

func (ack *AckT) handleUnenroll(ctx context.Context, zlog zerolog.Logger, agent *model.Agent) error {
	span, ctx := apm.StartSpan(ctx, "ackUnenroll", "process")
	defer span.End()

	apiKeys := agent.APIKeyIDs()
	zlog.Info().Any("fleet.policy.apiKeyIDsToRetire", apiKeys).Msg("handleUnenroll invalidate API keys")
	ack.invalidateAPIKeys(ctx, zlog, apiKeys, "")

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

func (ack *AckT) handleUpgrade(ctx context.Context, zlog zerolog.Logger, agent *model.Agent, event UpgradeEvent) error {
	span, ctx := apm.StartSpan(ctx, "ackUpgrade", "process")
	defer span.End()
	now := time.Now().UTC().Format(time.RFC3339)
	doc := bulk.UpdateFields{}
	if event.Error != nil {
		// if the payload indicates a retry, mark change the upgrade status to retrying.
		if event.Payload == nil {
			zlog.Info().Msg("marking agent upgrade as failed, agent logs contain failure message")
			doc = bulk.UpdateFields{
				dl.FieldUpgradeStartedAt: nil,
				dl.FieldUpgradeStatus:    "failed",
			}
		} else if event.Payload.Retry {
			zlog.Info().Int("retry_attempt", event.Payload.RetryAttempt).Msg("marking agent upgrade as retrying")
			doc[dl.FieldUpgradeStatus] = "retrying" // Keep FieldUpgradeStatedAt abd FieldUpgradeded at to original values
		} else {
			zlog.Info().Int("retry_attempt", event.Payload.RetryAttempt).Msg("marking agent upgrade as failed, agent logs contain failure message")
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
		if agent.UpgradeDetails == nil {
			doc[dl.FieldUpgradeAttempts] = nil
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
		Str(ecs.AgentID, agent.Agent.ID).
		Str(ecs.ActionID, event.ActionId).
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
// agent record without a check could set the revision for the wrong
// policy.  This script should be coupled with a "retry_on_conflict" parameter
// to allow for *other* changes to the agent record while we running the script.
// (For example, say the background bulk check-in timestamp update task fires)
//
// WARNING: This assumes the input data is sanitized.

const kUpdatePolicyPrefix = `{"script":{"lang":"painless","source":"if (ctx._source.policy_id == params.id) {ctx._source.remove('default_api_key_history');ctx._source.` +
	dl.FieldPolicyRevisionIdx +
	` = params.rev;ctx._source.` +
	dl.FieldUpdatedAt +
	` = params.ts;} else {ctx.op = \"noop\";}","params": {"id":"`

func makeUpdatePolicyBody(policyID string, newRev int64) []byte {
	var buf bytes.Buffer
	buf.Grow(410)

	//  Not pretty, but fast.
	buf.WriteString(kUpdatePolicyPrefix)
	buf.WriteString(policyID)
	buf.WriteString(`","rev":`)
	buf.WriteString(strconv.FormatInt(newRev, 10))
	buf.WriteString(`,"ts":"`)
	buf.WriteString(time.Now().UTC().Format(time.RFC3339))
	buf.WriteString(`"}}}`)

	return buf.Bytes()
}

func invalidateAPIKeys(ctx context.Context, zlog zerolog.Logger, bulk bulk.Bulk, toRetireAPIKeyIDs []model.ToRetireAPIKeyIdsItems, skip string) {
	ids := make([]string, 0, len(toRetireAPIKeyIDs))
	remoteIds := make(map[string][]string)
	for _, k := range toRetireAPIKeyIDs {
		if k.ID == skip || k.ID == "" {
			continue
		}
		if k.Output != "" {
			if remoteIds[k.Output] == nil {
				remoteIds[k.Output] = make([]string, 0)
			}
			remoteIds[k.Output] = append(remoteIds[k.Output], k.ID)
		} else {
			ids = append(ids, k.ID)
		}
	}
	if len(ids) > 0 {
		zlog.Info().Strs("fleet.policy.apiKeyIDsToRetire", ids).Msg("Invalidate old API keys")
		if err := bulk.APIKeyInvalidate(ctx, ids...); err != nil {
			zlog.Info().Err(err).Strs("ids", ids).Msg("Failed to invalidate API keys")
		}
	}
	// using remote es bulker to invalidate api key
	for outputName, outputIds := range remoteIds {
		outputBulk := bulk.GetBulker(outputName)

		if outputBulk == nil {
			// read output config from .fleet-policies, not filtering by policy id as agent could be reassigned
			policy, err := dl.QueryOutputFromPolicy(ctx, bulk, outputName)
			if err != nil || policy == nil {
				zlog.Warn().Str(ecs.PolicyOutputName, outputName).Any("ids", outputIds).Msg("Output policy not found, API keys will be orphaned")
			} else {
				outputBulk, _, err = bulk.CreateAndGetBulker(ctx, zlog, outputName, policy.Data.Outputs)
				if err != nil {
					zlog.Warn().Str(ecs.PolicyOutputName, outputName).Any("ids", outputIds).Msg("Failed to recreate output bulker, API keys will be orphaned")
				}
			}
		}
		if outputBulk != nil {
			if err := outputBulk.APIKeyInvalidate(ctx, outputIds...); err != nil {
				zlog.Info().Err(err).Strs("ids", outputIds).Str(ecs.PolicyOutputName, outputName).Msg("Failed to invalidate API keys")
			}
		}
	}
}
