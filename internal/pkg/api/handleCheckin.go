// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/action"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/hashicorp/go-version"
	"github.com/miolini/datacounter"
	"github.com/rs/zerolog"

	"go.elastic.co/apm/module/apmhttp/v2"
	"go.elastic.co/apm/v2"
)

var (
	ErrAgentNotFound          = errors.New("agent not found")
	ErrNoPolicyOutput         = errors.New("output section not found")
	ErrFailInjectAPIKey       = errors.New("failure to inject api key")
	ErrInvalidUpgradeMetadata = errors.New("invalid upgrade metadata")
)

const (
	kEncodingGzip  = "gzip"
	FailedStatus   = "FAILED"
	DegradedStatus = "DEGRADED"
)

// validActionTypes is a map of action.type and if they are valid
// unlisted or invalid types are removed with filterActions().
// action types should have a corresponding case in convertActionData.
var validActionTypes = map[string]bool{
	string(CANCEL):             true,
	string(INPUTACTION):        true,
	string(POLICYREASSIGN):     true,
	string(REQUESTDIAGNOSTICS): true,
	string(SETTINGS):           true,
	string(UNENROLL):           true,
	string(UPGRADE):            true,
	string(MIGRATE):            true,
}

type CheckinT struct {
	verCon version.Constraints
	cfg    *config.Server
	cache  cache.Cache
	bc     *checkin.Bulk
	pm     policy.Monitor
	gcp    monitor.GlobalCheckpointProvider
	ad     *action.Dispatcher
	tr     *action.TokenResolver

	// gwPool is a gzip.Writer pool intended to lower the amount of writers created when responding to checkin requests.
	// gzip.Writer allocations are expensive (~1.2MB each) and can exhaust an instance's memory if a lot of concurrent responses are sent (this occurs when a mass-action such as an upgrade is detected).
	// effectiveness of the pool is controlled by rate limiter configured through the limit.action_limit attribute.
	gwPool sync.Pool
	bulker bulk.Bulk
}

func NewCheckinT(
	verCon version.Constraints,
	cfg *config.Server,
	c cache.Cache,
	bc *checkin.Bulk,
	pm policy.Monitor,
	gcp monitor.GlobalCheckpointProvider,
	ad *action.Dispatcher,
	bulker bulk.Bulk,
) (*CheckinT, error) {
	tr, err := action.NewTokenResolver(bulker)
	if err != nil {
		return nil, err
	}
	ct := &CheckinT{
		verCon: verCon,
		cfg:    cfg,
		cache:  c,
		bc:     bc,
		pm:     pm,
		gcp:    gcp,
		ad:     ad,
		tr:     tr,
		gwPool: sync.Pool{
			New: func() any {
				zipper, err := gzip.NewWriterLevel(io.Discard, cfg.CompressionLevel)
				if err != nil {
					panic(err)
				}
				return zipper
			},
		},
		bulker: bulker,
	}

	return ct, nil
}

func (ct *CheckinT) handleCheckin(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, id, userAgent string) error {
	start := time.Now()

	agent, err := authAgent(r, &id, ct.bulker, ct.cache)
	if err != nil {
		// invalidate remote API keys of force unenrolled agents
		if errors.Is(err, ErrAgentInactive) && agent != nil {
			ctx := zlog.WithContext(r.Context())
			invalidateAPIKeysOfInactiveAgent(ctx, zlog, ct.bulker, agent)
		}
		return err
	}

	zlog = zlog.With().Str(LogAccessAPIKeyID, agent.AccessAPIKeyID).Logger()
	ctx := zlog.WithContext(r.Context())
	r = r.WithContext(ctx)

	ver, err := validateUserAgent(r.Context(), zlog, userAgent, ct.verCon)
	if err != nil {
		return err
	}

	// Safely check if the agent version is different, return empty string otherwise
	newVer := agent.CheckDifferentVersion(ver)
	return ct.ProcessRequest(zlog, w, r, start, agent, newVer)
}

func invalidateAPIKeysOfInactiveAgent(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agent *model.Agent) {
	remoteAPIKeys := make([]model.ToRetireAPIKeyIdsItems, 0)
	apiKeys := agent.APIKeyIDs()
	for _, key := range apiKeys {
		if key.Output != "" {
			remoteAPIKeys = append(remoteAPIKeys, key)
		}
	}
	zlog.Info().Any("fleet.policy.apiKeyIDsToRetire", remoteAPIKeys).Msg("handleCheckin invalidate remote API keys")
	invalidateAPIKeys(ctx, zlog, bulker, remoteAPIKeys, "")
}

// validatedCheckin is a struct to wrap all the things that validateRequest returns.
type validatedCheckin struct {
	req             *CheckinRequest
	dur             time.Duration
	rawMeta         []byte
	rawComp         []byte
	seqno           sqn.SeqNo
	unhealthyReason *[]string
}

func (ct *CheckinT) validateRequest(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, start time.Time, agent *model.Agent) (validatedCheckin, error) {
	span, ctx := apm.StartSpan(r.Context(), "validateRequest", "validate")
	defer span.End()

	body := r.Body
	// Limit the size of the body to prevent malicious agent from exhausting RAM in server
	if ct.cfg.Limits.CheckinLimit.MaxBody > 0 {
		body = http.MaxBytesReader(w, body, ct.cfg.Limits.CheckinLimit.MaxBody)
	}
	readCounter := datacounter.NewReaderCounter(body)

	var val validatedCheckin
	var req CheckinRequest
	decoder := json.NewDecoder(readCounter)
	if err := decoder.Decode(&req); err != nil {
		return val, &BadRequestErr{msg: "unable to decode checkin request", nextErr: err}
	}
	cntCheckin.bodyIn.Add(readCounter.Count())

	if req.Status == CheckinRequestStatus("") {
		return val, &BadRequestErr{msg: "checkin status missing"}
	}
	if len(req.Message) == 0 {
		zlog.Warn().Msg("checkin request method is empty.")
	}

	var pDur time.Duration
	var err error
	if req.PollTimeout != nil {
		pDur, err = time.ParseDuration(*req.PollTimeout)
		if err != nil {
			return val, &BadRequestErr{msg: "poll_timeout cannot be parsed as duration", nextErr: err}
		}
	}

	pollDuration := ct.cfg.Timeouts.CheckinLongPoll
	// set the pollDuration if pDur parsed from poll_timeout was a non-zero value
	// sets timeout is set to max(1m, min(pDur-2m, max poll time))
	// sets the response write timeout to max(2m, timeout+1m)
	if pDur != time.Duration(0) {
		pollDuration = pDur - (2 * time.Minute)
		if pollDuration > ct.cfg.Timeouts.CheckinMaxPoll {
			pollDuration = ct.cfg.Timeouts.CheckinMaxPoll
		}
		if pollDuration < time.Minute {
			pollDuration = time.Minute
		}

		wTime := pollDuration + time.Minute
		rc := http.NewResponseController(w)
		if err := rc.SetWriteDeadline(start.Add(wTime)); err != nil {
			zlog.Warn().Err(err).Time("write_deadline", start.Add(wTime)).Msg("Unable to set checkin write deadline.")
		} else {
			zlog.Trace().Time("write_deadline", start.Add(wTime)).Msg("Request write deadline set.")
		}
	}
	zlog.Trace().Dur("pollDuration", pollDuration).Msg("Request poll duration set.")

	// Compare local_metadata content and update if different
	rawMeta, err := parseMeta(zlog, agent, &req)
	if err != nil {
		return val, &BadRequestErr{msg: "unable to parse meta", nextErr: err}
	}

	// Compare agent_components content and update if different
	rawComponents, unhealthyReason, err := parseComponents(zlog, agent, &req)
	if err != nil {
		return val, err
	}

	// Resolve AckToken from request, fallback on the agent record
	seqno, err := ct.resolveSeqNo(ctx, zlog, req, agent)
	if err != nil {
		return val, err
	}

	return validatedCheckin{
		req:             &req,
		dur:             pollDuration,
		rawMeta:         rawMeta,
		rawComp:         rawComponents,
		seqno:           seqno,
		unhealthyReason: unhealthyReason,
	}, nil
}

func (ct *CheckinT) ProcessRequest(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, start time.Time, agent *model.Agent, ver string) error {
	zlog = zlog.With().
		Str(logger.AgentID, agent.Id).Logger()
	validated, err := ct.validateRequest(zlog, w, r, start, agent)
	if err != nil {
		return err
	}
	req := validated.req
	pollDuration := validated.dur
	rawMeta := validated.rawMeta
	rawComponents := validated.rawComp
	seqno := validated.seqno
	unhealthyReason := validated.unhealthyReason

	// Handle upgrade details for agents using the new 8.11 upgrade details field of the checkin.
	// Older agents will communicate any issues with upgrades via the Ack endpoint.
	if err := ct.processUpgradeDetails(r.Context(), agent, req.UpgradeDetails); err != nil {
		return fmt.Errorf("failed to update upgrade_details: %w", err)
	}

	// Subscribe to actions dispatcher
	aSub := ct.ad.Subscribe(zlog, agent.Id, seqno)
	defer ct.ad.Unsubscribe(zlog, aSub)
	actCh := aSub.Ch()

	// use revision_idx=0 if the agent has a single output where no API key is defined
	// This will force the policy monitor to emit a new policy to regerate API keys
	revID := agent.PolicyRevisionIdx
	for _, output := range agent.Outputs {
		if output.APIKey == "" {
			revID = 0
			break
		}
	}

	// Subscribe to policy manager for changes on PolicyId > policyRev
	sub, err := ct.pm.Subscribe(agent.Id, agent.PolicyID, revID)
	if err != nil {
		return fmt.Errorf("subscribe policy monitor: %w", err)
	}
	defer func() {
		err := ct.pm.Unsubscribe(sub)
		if err != nil {
			zlog.Error().Err(err).Str(logger.PolicyID, agent.PolicyID).Msg("unable to unsubscribe from policy")
		}
	}()

	// Update check-in timestamp on timeout
	tick := time.NewTicker(ct.cfg.Timeouts.CheckinTimestamp)
	defer tick.Stop()

	setupDuration := time.Since(start)
	pollDuration, jitter := calcPollDuration(zlog, pollDuration, setupDuration, ct.cfg.Timeouts.CheckinJitter)

	zlog.Debug().
		Str("status", string(req.Status)).
		Str("seqNo", seqno.String()).
		Dur("setupDuration", setupDuration).
		Dur("jitter", jitter).
		Dur("pollDuration", pollDuration).
		Msg("checkin start long poll")

	// Chill out for a bit. Long poll.
	longPoll := time.NewTicker(pollDuration)
	defer longPoll.Stop()

	// Initial update on checkin, and any user fields that might have changed
	// Run a script to remove audit_unenrolled_* and unenrolled_at attributes if one is set on checkin.
	// 8.16.x releases would incorrectly set unenrolled_at
	err = ct.bc.CheckIn(agent.Id, string(req.Status), req.Message, rawMeta, rawComponents, seqno, ver, unhealthyReason, agent.AuditUnenrolledReason != "" || agent.UnenrolledAt != "")
	if err != nil {
		zlog.Error().Err(err).Str(logger.AgentID, agent.Id).Msg("checkin failed")
	}

	// Initial fetch for pending actions
	var (
		actions  []Action
		ackToken string
	)

	// Check agent pending actions first
	pendingActions, err := ct.fetchAgentPendingActions(r.Context(), seqno, agent.Id)
	if err != nil {
		return err
	}
	pendingActions = filterActions(zlog, agent.Id, pendingActions)
	actions, ackToken = convertActions(zlog, agent.Id, pendingActions)

	span, ctx := apm.StartSpan(r.Context(), "longPoll", "process")

	if len(actions) == 0 {
	LOOP:
		for {
			select {
			case <-ctx.Done():
				defer span.End()
				// If the request context is canceled, the API server is shutting down.
				// We want to immediately stop the long-poll and return a 200 with the ackToken and no actions.
				if errors.Is(ctx.Err(), context.Canceled) {
					resp := CheckinResponse{
						AckToken: &ackToken,
						Action:   "checkin",
					}
					return ct.writeResponse(zlog, w, r, agent, resp)
				}
				return ctx.Err()
			case acdocs := <-actCh:
				var acs []Action
				acdocs = filterActions(zlog, agent.Id, acdocs)
				acs, ackToken = convertActions(zlog, agent.Id, acdocs)
				actions = append(actions, acs...)
				break LOOP
			case policy := <-sub.Output():
				actionResp, err := processPolicy(ctx, zlog, ct.bulker, agent, policy)
				if err != nil {
					span.End()
					return fmt.Errorf("processPolicy: %w", err)
				}
				actions = append(actions, *actionResp)
				break LOOP
			case <-longPoll.C:
				zlog.Trace().Msg("fire long poll")
				break LOOP
			case <-tick.C:
				err := ct.bc.CheckIn(agent.Id, string(req.Status), req.Message, nil, rawComponents, nil, ver, unhealthyReason, false)
				if err != nil {
					zlog.Error().Err(err).Str(logger.AgentID, agent.Id).Msg("checkin failed")
				}
			}
		}
	}
	span.End()

	resp := CheckinResponse{
		AckToken: &ackToken,
		Action:   "checkin",
		Actions:  &actions,
	}

	return ct.writeResponse(zlog, w, r, agent, resp)
}

func (ct *CheckinT) verifyActionExists(vCtx context.Context, vSpan *apm.Span, agent *model.Agent, details *UpgradeDetails) (*model.Action, error) {
	action, ok := ct.cache.GetAction(details.ActionId)
	if !ok {
		actions, err := dl.FindAction(vCtx, ct.bulker, details.ActionId)
		if err != nil {
			vSpan.End()
			return nil, fmt.Errorf("unable to find upgrade_details action: %w", err)
		}
		if len(actions) == 0 {
			vSpan.End()
			zerolog.Ctx(vCtx).Warn().Msgf("upgrade_details no action for id %q found (agent id %q)", details.ActionId, agent.Agent.ID)
			return nil, nil
		}
		action = actions[0]
		ct.cache.SetAction(action)
	}
	vSpan.End()
	return &action, nil
}

// processUpgradeDetails will verify and set the upgrade_details section of an agent document based on checkin value.
// if the agent doc and checkin details are both nil the method is a nop
// if the checkin upgrade_details is nil but there was a previous value in the agent doc, fleet-server treats it as a successful upgrade
// otherwise the details are validated; action_id is checked and upgrade_details.metadata is validated based on upgrade_details.state and the agent doc is updated.
func (ct *CheckinT) processUpgradeDetails(ctx context.Context, agent *model.Agent, details *UpgradeDetails) error {
	if details == nil {
		err := ct.markUpgradeComplete(ctx, agent)
		if err != nil {
			return err
		}
		return nil
	}
	// update docs with in progress details

	vSpan, vCtx := apm.StartSpan(ctx, "Check update action", "validate")
	action, err := ct.verifyActionExists(ctx, vSpan, agent, details)
	if err != nil {
		return err
	}
	if action == nil {
		return nil
	}

	// link action with APM spans
	var links []apm.SpanLink
	if ct.bulker.HasTracer() && action.Traceparent != "" {
		traceCtx, err := apmhttp.ParseTraceparentHeader(action.Traceparent)
		if err != nil {
			zerolog.Ctx(vCtx).Trace().Err(err).Msgf("Error parsing traceparent: %s %s", action.Traceparent, err)
		} else {
			links = []apm.SpanLink{
				{
					Trace: traceCtx.Trace,
					Span:  traceCtx.Span,
				},
			}
		}
	}
	span, ctx := apm.StartSpanOptions(ctx, "Process upgrade details", "process", apm.SpanOptions{Links: links})
	span.Context.SetLabel("action_id", details.ActionId)
	span.Context.SetLabel("agent_id", agent.Agent.ID)
	defer span.End()

	// validate metadata with state
	vSpan, _ = apm.StartSpan(ctx, "validateUpgradeMetadata", "validate")
	switch details.State {
	case UpgradeDetailsStateUPGDOWNLOADING:
		if details.Metadata == nil {
			vSpan.End()
			break // no validation
		}
		upgradeDetails, err := details.Metadata.AsUpgradeMetadataDownloading()
		if err != nil {
			vSpan.End()
			return fmt.Errorf("%w %s: %w", ErrInvalidUpgradeMetadata, UpgradeDetailsStateUPGDOWNLOADING, err)
		}
		if err := details.Metadata.FromUpgradeMetadataDownloading(upgradeDetails); err != nil {
			vSpan.End()
			return fmt.Errorf("%w %s: unable to repack metadata: %w", ErrInvalidUpgradeMetadata, UpgradeDetailsStateUPGDOWNLOADING, err)
		}
	case UpgradeDetailsStateUPGFAILED:
		if details.Metadata == nil {
			vSpan.End()
			return fmt.Errorf("%w: metadata missing", ErrInvalidUpgradeMetadata)
		}
		meta, err := details.Metadata.AsUpgradeMetadataFailed()
		if err != nil {
			vSpan.End()
			return fmt.Errorf("%w %s: %w", ErrInvalidUpgradeMetadata, UpgradeDetailsStateUPGFAILED, err)
		}
		if meta.ErrorMsg == "" {
			vSpan.End()
			return fmt.Errorf("%w: %s metadata contains empty error_msg attribute", ErrInvalidUpgradeMetadata, UpgradeDetailsStateUPGFAILED)
		}
		// Repack metadata in failed case as the agent may send UPG_DOWNLOADING attributes.
		if err = details.Metadata.FromUpgradeMetadataFailed(meta); err != nil {
			vSpan.End()
			return fmt.Errorf("%w %s: unable to repack metadata: %w", ErrInvalidUpgradeMetadata, UpgradeDetailsStateUPGFAILED, err)
		}
	case UpgradeDetailsStateUPGSCHEDULED:
		if details.Metadata == nil {
			vSpan.End()
			return fmt.Errorf("%w: metadata missing", ErrInvalidUpgradeMetadata)
		}
		meta, err := details.Metadata.AsUpgradeMetadataScheduled()
		if err != nil {
			vSpan.End()
			return fmt.Errorf("%w %s: %w", ErrInvalidUpgradeMetadata, UpgradeDetailsStateUPGSCHEDULED, err)
		}
		if meta.ScheduledAt.IsZero() {
			vSpan.End()
			return fmt.Errorf("%w: %s metadata contains empty scheduled_at attribute", ErrInvalidUpgradeMetadata, UpgradeDetailsStateUPGSCHEDULED)

		}
	default:
	}
	vSpan.End()

	doc := bulk.UpdateFields{
		dl.FieldUpgradeDetails: details,
	}
	if agent.UpgradeAttempts != nil && details.State == UpgradeDetailsStateUPGWATCHING {
		doc[dl.FieldUpgradeAttempts] = nil
	}

	body, err := doc.Marshal()
	if err != nil {
		return err
	}
	return ct.bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3))
}

func (ct *CheckinT) markUpgradeComplete(ctx context.Context, agent *model.Agent) error {
	// nop if there are no checkin details, and the agent has no details
	if agent.UpgradeDetails == nil {
		return nil
	}
	span, ctx := apm.StartSpan(ctx, "Mark update complete", "update")
	span.Context.SetLabel("agent_id", agent.Agent.ID)
	defer span.End()
	// if the checkin had no details, but agent has details treat like a successful upgrade
	doc := bulk.UpdateFields{
		dl.FieldUpgradeDetails:   nil,
		dl.FieldUpgradeStartedAt: nil,
		dl.FieldUpgradeStatus:    nil,
		dl.FieldUpgradedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	body, err := doc.Marshal()
	if err != nil {
		return err
	}
	return ct.bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3))
}

func (ct *CheckinT) writeResponse(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, agent *model.Agent, resp CheckinResponse) error {
	ctx := r.Context()
	var links []apm.SpanLink
	if ct.bulker.HasTracer() {
		for _, a := range fromPtr(resp.Actions) {
			if fromPtr(a.Traceparent) != "" {
				traceContext, err := apmhttp.ParseTraceparentHeader(fromPtr(a.Traceparent))
				if err != nil {
					zlog.Debug().Err(err).Msg("unable to parse traceparent header")
					continue
				}

				zlog.Debug().Str("traceparent", fromPtr(a.Traceparent)).Msgf("✅ parsed traceparent header: %s", fromPtr(a.Traceparent))

				links = append(links, apm.SpanLink{
					Trace: traceContext.Trace,
					Span:  traceContext.Span,
				})
			}
		}
	}

	if len(fromPtr(resp.Actions)) > 0 {
		var span *apm.Span
		span, ctx = apm.StartSpanOptions(ctx, "action delivery", "fleet-server", apm.SpanOptions{
			Links: links,
		})
		span.Context.SetLabel("action_count", len(fromPtr(resp.Actions)))
		span.Context.SetLabel("agent_id", agent.Id)
		defer span.End()
	}

	for _, action := range fromPtr(resp.Actions) {
		zlog.Info().
			Str("ackToken", fromPtr(resp.AckToken)).
			Str("createdAt", action.CreatedAt).
			Str(logger.ActionID, action.Id).
			Str(logger.ActionType, string(action.Type)).
			Str("inputType", action.InputType).
			Int64("timeout", fromPtr(action.Timeout)).
			Msg("Action delivered to agent on checkin")
	}
	rSpan, _ := apm.StartSpan(ctx, "response", "write")
	defer rSpan.End()

	payload, err := json.Marshal(&resp)
	if err != nil {
		return fmt.Errorf("writeResponse marshal: %w", err)
	}

	compressionLevel := ct.cfg.CompressionLevel
	compressThreshold := ct.cfg.CompressionThresh

	if len(payload) > compressThreshold && compressionLevel != flate.NoCompression && acceptsEncoding(r, kEncodingGzip) {
		wrCounter := datacounter.NewWriterCounter(w)

		zipper, _ := ct.gwPool.Get().(*gzip.Writer)

		defer ct.gwPool.Put(zipper)
		zipper.Reset(wrCounter)

		w.Header().Set("Content-Encoding", kEncodingGzip)
		if _, err = zipper.Write(payload); err != nil {
			return fmt.Errorf("writeResponse gzip write: %w", err)
		}

		if err = zipper.Close(); err != nil {
			err = fmt.Errorf("writeResponse gzip close: %w", err)
		}

		cntCheckin.bodyOut.Add(wrCounter.Count())

		zlog.Trace().
			Err(err).
			Int("lvl", compressionLevel).
			Int("srcSz", len(payload)).
			Uint64("dstSz", wrCounter.Count()).
			Msg("compressing checkin response")
	} else {
		var nWritten int
		nWritten, err = w.Write(payload)
		cntCheckin.bodyOut.Add(uint64(nWritten)) //nolint:gosec // disable G115

		if err != nil {
			err = fmt.Errorf("writeResponse payload: %w", err)
		}
	}

	return err
}

func acceptsEncoding(r *http.Request, encoding string) bool {
	for _, v := range r.Header.Values("Accept-Encoding") {
		if v == encoding {
			return true
		}
	}
	return false
}

// Resolve AckToken from request, fallback on the agent record
func (ct *CheckinT) resolveSeqNo(ctx context.Context, zlog zerolog.Logger, req CheckinRequest, agent *model.Agent) (sqn.SeqNo, error) {
	span, ctx := apm.StartSpan(ctx, "resolveSeqNo", "validate")
	defer span.End()
	var err error
	// Resolve AckToken from request, fallback on the agent record
	ackToken := req.AckToken
	var seqno sqn.SeqNo = agent.ActionSeqNo

	if ct.tr != nil && ackToken != nil {
		var sn int64
		sn, err = ct.tr.Resolve(ctx, *ackToken)
		if err != nil {
			if errors.Is(err, dl.ErrNotFound) {
				zlog.Debug().Str("token", *ackToken).Msg("revision token not found")
				err = nil
				// should be left the ActionSeqNo if no ackToken, otherwise would be overwritten with 0 on a Fleet Server restart
				return seqno, err
			} else {
				return seqno, fmt.Errorf("resolveSeqNo: %w", err)
			}
		}
		seqno = []int64{sn}
	}
	return seqno, err
}

func (ct *CheckinT) fetchAgentPendingActions(ctx context.Context, seqno sqn.SeqNo, agentID string) ([]model.Action, error) {
	actions, err := dl.FindAgentActions(ctx, ct.bulker, seqno, ct.gcp.GetCheckpoint(), agentID)
	if err != nil {
		return nil, fmt.Errorf("fetchAgentPendingActions: %w", err)
	}

	return actions, err
}

// filterActions removes the POLICY_CHANGE, UPDATE_TAGS, FORCE_UNENROLL action from the passed list as well as any unknown action types.
// The source of this list are documents from the fleet actions index.
// The POLICY_CHANGE action that the agent receives are generated by the fleet-server when it detects a different policy in processRequest()
// The UPDATE_TAGS, FORCE_UNENROLL actions are UI only actions, should not be delivered to agents
func filterActions(zlog zerolog.Logger, agentID string, actions []model.Action) []model.Action {
	resp := make([]model.Action, 0, len(actions))
	for _, action := range actions {
		if valid := validActionTypes[action.Type]; !valid {
			zlog.Info().Str(logger.AgentID, agentID).Str(logger.ActionID, action.ActionID).Str(logger.ActionType, action.Type).Msg("Removing action found in index from check in response")
			continue
		}
		resp = append(resp, action)
	}
	return resp
}

// convertActionData converts the passed raw message data to Action_Data using aType as a discriminator.
//
// raw is first parsed into the action-specific data struct then passed into Action_Data in order to remove any undefined keys.
//
// TODO: There is a lot of repitition in this method we should try to clean up.
//
//nolint:nakedret // FIXME try to refactor this in the future
func convertActionData(aType ActionType, raw json.RawMessage) (ad Action_Data, err error) {
	switch aType {
	case CANCEL:
		d := ActionCancel{}
		err = json.Unmarshal(raw, &d)
		if err != nil {
			return
		}
		err = ad.FromActionCancel(d)
		return
	case INPUTACTION:
		d := ActionInputAction{}
		err = json.Unmarshal(raw, &d)
		if err != nil {
			return
		}
		err = ad.FromActionInputAction(d)
		return
	case POLICYREASSIGN:
		d := ActionPolicyReassign{}
		err = json.Unmarshal(raw, &d)
		if err != nil {
			return
		}
		err = ad.FromActionPolicyReassign(d)
		return
	case SETTINGS:
		d := ActionSettings{}
		err = json.Unmarshal(raw, &d)
		if err != nil {
			return
		}
		err = ad.FromActionSettings(d)
		return
	case UPGRADE:
		d := ActionUpgrade{}
		err = json.Unmarshal(raw, &d)
		if err != nil {
			return
		}
		err = ad.FromActionUpgrade(d)
		return
	case REQUESTDIAGNOSTICS:
		d := ActionRequestDiagnostics{}
		// NOTE: action data was added to diagnostics actions in #3333
		// fleet ui creates actions without a data attribute and fleet-server needs to be backwards compatible with these actions.
		if raw == nil {
			return
		}
		err = json.Unmarshal(raw, &d)
		if err != nil {
			return
		}
		err = ad.FromActionRequestDiagnostics(d)
		return
	case UNENROLL: // Action types with no data
		return ad, nil
	case MIGRATE:
		d := ActionMigrate{}
		err = json.Unmarshal(raw, &d)
		if err != nil {
			return
		}
		err = ad.FromActionMigrate(d)
		return
	default:
		return ad, fmt.Errorf("data conversion unsupported action type: %s", aType)
	}
}

func convertActions(zlog zerolog.Logger, agentID string, actions []model.Action) ([]Action, string) {
	var ackToken string
	sz := len(actions)

	respList := make([]Action, 0, sz)
	for _, action := range actions {
		ad, err := convertActionData(ActionType(action.Type), action.Data)
		if err != nil {
			zlog.Error().Err(err).Str(logger.ActionID, action.ActionID).Str(logger.ActionType, action.Type).Msg("Failed to convert action.Data")
			continue
		}
		r := Action{
			AgentId:   agentID,
			CreatedAt: action.Timestamp,
			Data:      ad,
			Id:        action.ActionID,
			Type:      ActionType(action.Type),
			InputType: action.InputType,
		}
		if action.StartTime != "" {
			r.StartTime = &action.StartTime
		}
		if action.Expiration != "" {
			r.Expiration = &action.Expiration
		}
		if action.Traceparent != "" {
			r.Traceparent = &action.Traceparent
		}
		if action.Timeout != 0 {
			r.Timeout = &action.Timeout
		}
		if action.Signed != nil {
			r.Signed = &ActionSignature{
				Data:      action.Signed.Data,
				Signature: action.Signed.Signature,
			}
		}
		respList = append(respList, r)
	}

	if sz > 0 {
		ackToken = actions[sz-1].Id
	}

	return respList, ackToken
}

// A new policy exists for this agent.  Perform the following:
//   - Generate and update default ApiKey if roles have changed.
//   - Rewrite the policy for delivery to the agent injecting the key material.
func processPolicy(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agent *model.Agent, pp *policy.ParsedPolicy) (*Action, error) {
	var links []apm.SpanLink = nil // set to a nil array to preserve default behaviour if no policy links are found
	if err := pp.Links.Trace.Validate(); err == nil {
		links = []apm.SpanLink{pp.Links}
	}
	span, ctx := apm.StartSpanOptions(ctx, "processPolicy", "process", apm.SpanOptions{Links: links})
	defer span.End()
	zlog = zlog.With().
		Str("fleet.ctx", "processPolicy").
		Int64(logger.RevisionIdx, pp.Policy.RevisionIdx).
		Str(LogPolicyID, pp.Policy.PolicyID).
		Logger()

	if len(pp.Policy.Data.Outputs) == 0 {
		return nil, ErrNoPolicyOutput
	}

	data := model.ClonePolicyData(pp.Policy.Data)
	for policyName, policyOutput := range data.Outputs {
		// NOTE: Not sure if output secret keys collected here include new entries, but they are collected for completeness
		ks, err := policy.ProcessOutputSecret(ctx, policyOutput, bulker) // makes a bulk request to get secret values
		if err != nil {
			return nil, fmt.Errorf("failed to process output secrets %q: %w",
				policyName, err)
		}
		pp.SecretKeys = append(pp.SecretKeys, ks...)
	}
	// Iterate through the policy outputs and prepare them
	for _, policyOutput := range pp.Outputs {
		if err := policyOutput.Prepare(ctx, zlog, bulker, agent, data.Outputs); err != nil {
			return nil, fmt.Errorf("failed to prepare output %q: %w",
				policyOutput.Name, err)
		}
	}
	// Add replace inputs with agent prepared version.
	data.Inputs = pp.Inputs

	// JSON transformations to turn a model.PolicyData into an Action.data
	p, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	d := PolicyData{}
	err = json.Unmarshal(p, &d)
	if err != nil {
		return nil, err
	}
	// remove duplicates from secretkeys
	slices.Sort(pp.SecretKeys)
	keys := slices.Compact(pp.SecretKeys)
	d.SecretPaths = &keys
	ad := Action_Data{}
	err = ad.FromActionPolicyChange(ActionPolicyChange{d})
	if err != nil {
		return nil, err
	}

	r := policy.RevisionFromPolicy(pp.Policy)
	resp := Action{
		AgentId:   agent.Id,
		CreatedAt: pp.Policy.Timestamp,
		Data:      ad,
		Id:        r.String(),
		Type:      POLICYCHANGE,
	}

	return &resp, nil
}

func getAgentAndVerifyAPIKeyID(ctx context.Context, bulker bulk.Bulk, agentID string, apiKeyID string) (*model.Agent, error) {
	span, ctx := apm.StartSpan(ctx, "getAgentAndVerifyAPIKeyID", "read")
	defer span.End()
	agent, err := dl.GetAgent(ctx, bulker, agentID)
	if err != nil {
		if errors.Is(err, dl.ErrNotFound) {
			err = ErrAgentNotFound
		} else {
			err = fmt.Errorf("GetAgent: %w", err)
		}
	}

	if agent.AccessAPIKeyID != apiKeyID {
		err = fmt.Errorf("invalid API Key ID %w", ErrAgentIdentity)
	}

	return &agent, err
}

func findAgentByAPIKeyID(ctx context.Context, bulker bulk.Bulk, id string) (*model.Agent, error) {
	span, ctx := apm.StartSpan(ctx, "findAgentByID", "search")
	defer span.End()
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByAssessAPIKeyID, dl.FieldAccessAPIKeyID, id)
	if err != nil {
		if errors.Is(err, dl.ErrNotFound) {
			err = ErrAgentNotFound
		} else {
			err = fmt.Errorf("findAgentByApiKeyId: %w", err)
		}
	}
	return &agent, err
}

// parseMeta compares the agent and the request local_metadata content
// and returns fields to update the agent record or nil
func parseMeta(zlog zerolog.Logger, agent *model.Agent, req *CheckinRequest) ([]byte, error) {
	if req.LocalMetadata == nil {
		return nil, nil
	}

	// Quick comparison first; compare the JSON payloads.
	// If the data is not consistently normalized, this short-circuit will not work.
	if bytes.Equal(*req.LocalMetadata, agent.LocalMetadata) {
		zlog.Trace().Msg("quick comparing local metadata is equal")
		return nil, nil
	}

	// Deserialize the request metadata
	var reqLocalMeta interface{}
	if err := json.Unmarshal(*req.LocalMetadata, &reqLocalMeta); err != nil {
		return nil, fmt.Errorf("parseMeta request: %w", err)
	}

	// If empty, don't step on existing data
	if reqLocalMeta == nil {
		return nil, nil
	}

	// Deserialize the agent's metadata copy. If it fails, it's ignored as it will just
	// be replaced with the correct contents from the clients checkin.
	var agentLocalMeta interface{}
	if err := json.Unmarshal(agent.LocalMetadata, &agentLocalMeta); err != nil {
		zlog.Warn().Err(err).Msg("local_metadata in document invalid; ignoring it")
	}

	var outMeta []byte

	// Compare the deserialized meta structures and return the bytes to update if different
	if !reflect.DeepEqual(reqLocalMeta, agentLocalMeta) {

		zlog.Trace().
			RawJSON("oldLocalMeta", agent.LocalMetadata).
			RawJSON("newLocalMeta", *req.LocalMetadata).
			Msg("local metadata not equal")

		zlog.Info().
			RawJSON("req.LocalMeta", *req.LocalMetadata).
			Msg("applying new local metadata")

		outMeta = *req.LocalMetadata
	}

	return outMeta, nil
}

func parseComponents(zlog zerolog.Logger, agent *model.Agent, req *CheckinRequest) ([]byte, *[]string, error) {
	var unhealthyReason []string

	// fallback to other if components don't exist
	if agent.UnhealthyReason == nil && (agent.LastCheckinStatus == FailedStatus || agent.LastCheckinStatus == DegradedStatus) {
		unhealthyReason = []string{"other"}
	} else {
		unhealthyReason = agent.UnhealthyReason
	}

	if req.Components == nil {
		return nil, &unhealthyReason, nil
	}

	// Quick comparison first; compare the JSON payloads.
	// If the data is not consistently normalized, this short-circuit will not work.
	if bytes.Equal(req.Components, agent.Components) {
		zlog.Trace().Msg("quick comparing agent components data is equal")
		return nil, &unhealthyReason, nil
	}

	// Deserialize the request components data
	var reqComponents []model.ComponentsItems
	if len(*req.Components) > 0 {
		if err := json.Unmarshal(*req.Components, &reqComponents); err != nil {
			return nil, &unhealthyReason, fmt.Errorf("parseComponents request: %w", err)
		}
	}

	// If empty, don't step on existing data
	if reqComponents == nil {
		return nil, &unhealthyReason, nil
	}

	// Deserialize the agent's components. If it fails, it's ignored as it will just
	// be replaced with the correct contents from the clients checkin.
	var agentComponents []model.ComponentsItems
	if err := json.Unmarshal(agent.Components, &agentComponents); err != nil {
		zlog.Warn().Err(err).Msg("components in document invalid; ignoring it")
	}

	var outComponents []byte

	// Compare the deserialized meta structures and return the bytes to update if different
	if !reflect.DeepEqual(reqComponents, agentComponents) {
		reqComponentsJSON, _ := json.Marshal(req.Components)
		zlog.Trace().
			Str("oldComponents", string(agent.Components)).
			Str("req.Components", string(reqComponentsJSON)).
			Msg("local components data is not equal")

		zlog.Info().Msg("applying new components data")

		outComponents = *req.Components
		compUnhealthyReason := calcUnhealthyReason(reqComponents)
		if len(compUnhealthyReason) > 0 {
			unhealthyReason = compUnhealthyReason
		}
	}

	zlog.Debug().Any("unhealthy_reason", unhealthyReason).Msg("unhealthy reason")

	return outComponents, &unhealthyReason, nil
}

func calcUnhealthyReason(reqComponents []model.ComponentsItems) []string {
	var unhealthyReason []string
	hasUnhealthyInput := false
	hasUnhealthyOutput := false
	hasUnhealthyComponent := false
	for _, component := range reqComponents {
		if component.Status == FailedStatus || component.Status == DegradedStatus {
			hasUnhealthyComponent = true
			for _, unit := range component.Units {
				if unit.Status == FailedStatus || unit.Status == DegradedStatus {
					switch unit.Type {
					case "input":
						hasUnhealthyInput = true
					case "output":
						hasUnhealthyOutput = true
					}
				}
			}
		}
	}
	unhealthyReason = make([]string, 0)
	if hasUnhealthyInput {
		unhealthyReason = append(unhealthyReason, "input")
	}
	if hasUnhealthyOutput {
		unhealthyReason = append(unhealthyReason, "output")
	}
	if !hasUnhealthyInput && !hasUnhealthyOutput && hasUnhealthyComponent {
		unhealthyReason = append(unhealthyReason, "other")
	}

	return unhealthyReason
}

func calcPollDuration(zlog zerolog.Logger, pollDuration, setupDuration, jitterDuration time.Duration) (time.Duration, time.Duration) {
	// Under heavy load, elastic may take along time to authorize the api key, many seconds to minutes.
	// Short circuit the long poll to take the setup delay into account.  This is particularly necessary
	// in cloud where the proxy will time us out after 10m20s causing unnecessary errors.
	if setupDuration >= pollDuration {
		zlog.Warn().
			Dur("setupDuration", setupDuration).
			Dur("pollDuration", pollDuration).
			Msg("excessive setup duration short cicuit long poll")
		// We took so long to setup that we need to exit immediately
		return time.Millisecond, time.Duration(0)
	} else {
		pollDuration -= setupDuration
		if setupDuration > (time.Second * 10) {
			zlog.Warn().
				Dur("setupDuration", setupDuration).
				Dur("pollDuration", pollDuration).
				Msg("checking poll duration decreased due to slow setup")
		}
	}

	var jitter time.Duration
	if jitterDuration != 0 {
		jitter = time.Duration(rand.Int63n(int64(jitterDuration))) //nolint:gosec // jitter time does not need to by generated from a crypto secure source
		if jitter < pollDuration {
			pollDuration = pollDuration - jitter
			zlog.Trace().Dur("poll", pollDuration).Msg("Long poll with jitter")
		}
	}

	return pollDuration, jitter
}
