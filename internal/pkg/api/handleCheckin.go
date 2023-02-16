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
	"math/rand"
	"net/http"
	"reflect"
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
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/hashicorp/go-version"
	"github.com/julienschmidt/httprouter"
	"github.com/miolini/datacounter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	ErrAgentNotFound    = errors.New("agent not found")
	ErrNoPolicyOutput   = errors.New("output section not found")
	ErrFailInjectAPIKey = errors.New("failure to inject api key")
)

const (
	kEncodingGzip = "gzip"
)

//nolint:dupl // function body calls different internal hander then handleAck
func (rt *Router) handleCheckin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	id := ps.ByName("id")

	reqID := r.Header.Get(logger.HeaderRequestID)

	zlog := log.With().
		Str(LogAgentID, id).
		Str(ECSHTTPRequestID, reqID).
		Logger()

	err := rt.ct.handleCheckin(&zlog, w, r, id)
	if err != nil {
		cntCheckin.IncError(err)
		resp := NewHTTPErrResp(err)

		zlog.WithLevel(resp.Level).
			Err(err).
			Int(ECSHTTPResponseCode, resp.StatusCode).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Msg("fail checkin")

		if err := resp.Write(w); err != nil {
			zlog.Error().Err(err).Msg("fail writing error response")
		}
	}
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
	tr *action.TokenResolver,
	bulker bulk.Bulk,
) *CheckinT {
	ct := &CheckinT{
		verCon: verCon,
		cfg:    cfg,
		cache:  c,
		bc:     bc,
		pm:     pm,
		gcp:    gcp,
		ad:     ad,
		tr:     tr,
		bulker: bulker,
	}

	return ct
}

func (ct *CheckinT) handleCheckin(zlog *zerolog.Logger, w http.ResponseWriter, r *http.Request, id string) error {
	start := time.Now()

	agent, err := authAgent(r, &id, ct.bulker, ct.cache)
	if err != nil {
		return err
	}

	// Pointer is passed in to allow UpdateContext by child function
	zlog.UpdateContext(func(ctx zerolog.Context) zerolog.Context {
		return ctx.Str(LogAccessAPIKeyID, agent.AccessAPIKeyID)
	})

	ver, err := validateUserAgent(*zlog, r, ct.verCon)
	if err != nil {
		return err
	}

	// Safely check if the agent version is different, return empty string otherwise
	newVer := agent.CheckDifferentVersion(ver)
	return ct.ProcessRequest(*zlog, w, r, start, agent, newVer)
}

func (ct *CheckinT) ProcessRequest(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, start time.Time, agent *model.Agent, ver string) error {

	ctx := r.Context()

	body := r.Body

	// Limit the size of the body to prevent malicious agent from exhausting RAM in server
	if ct.cfg.Limits.CheckinLimit.MaxBody > 0 {
		body = http.MaxBytesReader(w, body, ct.cfg.Limits.CheckinLimit.MaxBody)
	}

	readCounter := datacounter.NewReaderCounter(body)

	var req CheckinRequest
	decoder := json.NewDecoder(readCounter)
	if err := decoder.Decode(&req); err != nil {
		return fmt.Errorf("decode checkin request: %w", err)
	}

	cntCheckin.bodyIn.Add(readCounter.Count())

	// Compare local_metadata content and update if different
	rawMeta, err := parseMeta(zlog, agent, &req)
	if err != nil {
		return err
	}

	// Compare agent_components content and update if different
	rawComponents, err := parseComponents(zlog, agent, &req)
	if err != nil {
		return err
	}

	// Resolve AckToken from request, fallback on the agent record
	seqno, err := ct.resolveSeqNo(ctx, zlog, req, agent)
	if err != nil {
		return err
	}

	// Subscribe to actions dispatcher
	aSub := ct.ad.Subscribe(agent.Id, seqno)
	defer ct.ad.Unsubscribe(aSub)
	actCh := aSub.Ch()

	// Subscribe to policy manager for changes on PolicyId > policyRev
	sub, err := ct.pm.Subscribe(agent.Id, agent.PolicyID, agent.PolicyRevisionIdx, agent.PolicyCoordinatorIdx)
	if err != nil {
		return fmt.Errorf("subscribe policy monitor: %w", err)
	}
	defer func() {
		err := ct.pm.Unsubscribe(sub)
		if err != nil {
			zlog.Error().Err(err).Str("policy_id", agent.PolicyID).Msg("unable to unsubscribe from policy")
		}
	}()

	// Update check-in timestamp on timeout
	tick := time.NewTicker(ct.cfg.Timeouts.CheckinTimestamp)
	defer tick.Stop()

	setupDuration := time.Since(start)
	pollDuration, jitter := calcPollDuration(zlog, ct.cfg, setupDuration)

	zlog.Debug().
		Str("status", req.Status).
		Str("seqNo", seqno.String()).
		Dur("setupDuration", setupDuration).
		Dur("jitter", jitter).
		Dur("pollDuration", pollDuration).
		Uint64("bodyCount", readCounter.Count()).
		Msg("checkin start long poll")

	// Chill out for a bit. Long poll.
	longPoll := time.NewTicker(pollDuration)
	defer longPoll.Stop()

	// Initial update on checkin, and any user fields that might have changed
	err = ct.bc.CheckIn(agent.Id, req.Status, req.Message, rawMeta, rawComponents, seqno, ver)
	if err != nil {
		zlog.Error().Err(err).Str("agent_id", agent.Id).Msg("checkin failed")
	}

	// Initial fetch for pending actions
	var (
		actions  []ActionResp
		ackToken string
	)

	// Check agent pending actions first
	pendingActions, err := ct.fetchAgentPendingActions(ctx, seqno, agent.Id)
	if err != nil {
		return err
	}
	pendingActions = filterActions(agent.Id, pendingActions)
	actions, ackToken = convertActions(agent.Id, pendingActions)

	if len(actions) == 0 {
	LOOP:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case acdocs := <-actCh:
				var acs []ActionResp
				acdocs = filterActions(agent.Id, acdocs)
				acs, ackToken = convertActions(agent.Id, acdocs)
				actions = append(actions, acs...)
				break LOOP
			case policy := <-sub.Output():
				actionResp, err := processPolicy(ctx, zlog, ct.bulker, agent.Id, policy)
				if err != nil {
					return fmt.Errorf("processPolicy: %w", err)
				}
				actions = append(actions, *actionResp)
				break LOOP
			case <-longPoll.C:
				zlog.Trace().Msg("fire long poll")
				break LOOP
			case <-tick.C:
				err := ct.bc.CheckIn(agent.Id, req.Status, req.Message, nil, rawComponents, nil, ver)
				if err != nil {
					zlog.Error().Err(err).Str("agent_id", agent.Id).Msg("checkin failed")
				}
			}
		}
	}

	for _, action := range actions {
		zlog.Info().
			Str("ackToken", ackToken).
			Str("createdAt", action.CreatedAt).
			Str("id", action.ID).
			Str("type", action.Type).
			Str("inputType", action.InputType).
			Int64("timeout", action.Timeout).
			Msg("Action delivered to agent on checkin")
	}

	resp := CheckinResponse{
		AckToken: ackToken,
		Action:   "checkin",
		Actions:  actions,
	}

	return ct.writeResponse(zlog, w, r, resp)
}

func (ct *CheckinT) writeResponse(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, resp CheckinResponse) error {

	payload, err := json.Marshal(&resp)
	if err != nil {
		return fmt.Errorf("writeResponse marshal: %w", err)
	}

	compressionLevel := ct.cfg.CompressionLevel
	compressThreshold := ct.cfg.CompressionThresh

	if len(payload) > compressThreshold && compressionLevel != flate.NoCompression && acceptsEncoding(r, kEncodingGzip) {

		wrCounter := datacounter.NewWriterCounter(w)

		zipper, err := gzip.NewWriterLevel(wrCounter, compressionLevel)
		if err != nil {
			return fmt.Errorf("writeResponse new gzip: %w", err)
		}

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
		cntCheckin.bodyOut.Add(uint64(nWritten))

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
	var err error
	// Resolve AckToken from request, fallback on the agent record
	ackToken := req.AckToken
	var seqno sqn.SeqNo = agent.ActionSeqNo

	if ct.tr != nil && ackToken != "" {
		var sn int64
		sn, err = ct.tr.Resolve(ctx, ackToken)
		if err != nil {
			if errors.Is(err, dl.ErrNotFound) {
				zlog.Debug().Str("token", ackToken).Msg("revision token not found")
				err = nil
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

// filterActions removes the POLICY_CHANGE, UPDATE_TAGS, FORCE_UNENROLL action from the passed list.
// The source of this list are documents from the fleet actions index.
// The POLICY_CHANGE action that the agent receives are generated by the fleet-server when it detects a different policy in processRequest()
// The UPDATE_TAGS, FORCE_UNENROLL actions are UI only actions, should not be delivered to agents
func filterActions(agentID string, actions []model.Action) []model.Action {
	resp := make([]model.Action, 0, len(actions))
	for _, action := range actions {
		ignoredTypes := map[string]bool{
			TypePolicyChange:  true,
			TypeUpdateTags:    true,
			TypeForceUnenroll: true,
		}
		if exists := ignoredTypes[action.Type]; exists {
			log.Info().Str("agent_id", agentID).Str("action_id", action.ActionID).Str("type", action.Type).Msg("Removing action found in index from check in response")
			continue
		}
		resp = append(resp, action)
	}
	return resp

}

func convertActions(agentID string, actions []model.Action) ([]ActionResp, string) {
	var ackToken string
	sz := len(actions)

	respList := make([]ActionResp, 0, sz)
	for _, action := range actions {
		ar := ActionResp{
			AgentID:    agentID,
			CreatedAt:  action.Timestamp,
			StartTime:  action.StartTime,
			Expiration: action.Expiration,
			Data:       action.Data,
			ID:         action.ActionID,
			Type:       action.Type,
			InputType:  action.InputType,
			Timeout:    action.Timeout,
		}

		if action.Signed != nil {
			ar.Signed = &ActionRespSigned{
				Data:      action.Signed.Data,
				Signature: action.Signed.Signature,
			}
		}
		respList = append(respList, ar)
	}

	if sz > 0 {
		ackToken = actions[sz-1].Id
	}

	return respList, ackToken
}

// A new policy exists for this agent.  Perform the following:
//   - Generate and update default ApiKey if roles have changed.
//   - Rewrite the policy for delivery to the agent injecting the key material.
func processPolicy(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agentID string, pp *policy.ParsedPolicy) (*ActionResp, error) {
	zlog = zlog.With().
		Str("fleet.ctx", "processPolicy").
		Int64("fleet.policyRevision", pp.Policy.RevisionIdx).
		Int64("fleet.policyCoordinator", pp.Policy.CoordinatorIdx).
		Str(LogPolicyID, pp.Policy.PolicyID).
		Logger()

	// Repull and decode the agent object. Do not trust the cache.
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldID, agentID)
	if err != nil {
		zlog.Error().Err(err).Msg("fail find agent record")
		return nil, err
	}

	// Parse the outputs maps in order to prepare the outputs
	const outputsProperty = "outputs"
	outputs, err := smap.Parse(pp.Fields[outputsProperty])
	if err != nil {
		return nil, err
	}

	if outputs == nil {
		return nil, ErrNoPolicyOutput
	}

	// Iterate through the policy outputs and prepare them
	for _, policyOutput := range pp.Outputs {
		err = policyOutput.Prepare(ctx, zlog, bulker, &agent, outputs)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare output %q:: %w",
				policyOutput.Name, err)
		}
	}

	outputRaw, err := json.Marshal(outputs)
	if err != nil {
		return nil, err
	}

	// Dupe field map; pp is immutable
	fields := make(map[string]json.RawMessage, len(pp.Fields))

	for k, v := range pp.Fields {
		fields[k] = v
	}

	// Update only the output fields to avoid duping the whole map
	fields[outputsProperty] = json.RawMessage(outputRaw)

	rewrittenPolicy := struct {
		Policy map[string]json.RawMessage `json:"policy"`
	}{fields}

	r := policy.RevisionFromPolicy(pp.Policy)
	resp := ActionResp{
		AgentID:   agent.Id,
		CreatedAt: pp.Policy.Timestamp,
		Data:      rewrittenPolicy,
		ID:        r.String(),
		Type:      TypePolicyChange,
	}

	return &resp, nil
}

func findAgentByAPIKeyID(ctx context.Context, bulker bulk.Bulk, id string) (*model.Agent, error) {
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

	// Quick comparison first; compare the JSON payloads.
	// If the data is not consistently normalized, this short-circuit will not work.
	if bytes.Equal(req.LocalMeta, agent.LocalMetadata) {
		zlog.Trace().Msg("quick comparing local metadata is equal")
		return nil, nil
	}

	// Deserialize the request metadata
	var reqLocalMeta interface{}
	if err := json.Unmarshal(req.LocalMeta, &reqLocalMeta); err != nil {
		return nil, fmt.Errorf("parseMeta request: %w", err)
	}

	// If empty, don't step on existing data
	if reqLocalMeta == nil {
		return nil, nil
	}

	// Deserialize the agent's metadata copy
	var agentLocalMeta interface{}
	if err := json.Unmarshal(agent.LocalMetadata, &agentLocalMeta); err != nil {
		return nil, fmt.Errorf("parseMeta local: %w", err)
	}

	var outMeta []byte

	// Compare the deserialized meta structures and return the bytes to update if different
	if !reflect.DeepEqual(reqLocalMeta, agentLocalMeta) {

		zlog.Trace().
			RawJSON("oldLocalMeta", agent.LocalMetadata).
			RawJSON("newLocalMeta", req.LocalMeta).
			Msg("local metadata not equal")

		zlog.Info().
			RawJSON("req.LocalMeta", req.LocalMeta).
			Msg("applying new local metadata")

		outMeta = req.LocalMeta
	}

	return outMeta, nil
}

func parseComponents(zlog zerolog.Logger, agent *model.Agent, req *CheckinRequest) ([]byte, error) {

	// Quick comparison first; compare the JSON payloads.
	// If the data is not consistently normalized, this short-circuit will not work.
	if bytes.Equal(req.Components, agent.Components) {
		zlog.Trace().Msg("quick comparing agent components data is equal")
		return nil, nil
	}

	// Deserialize the request components data
	var reqComponents interface{}
	if len(req.Components) > 0 {
		if err := json.Unmarshal(req.Components, &reqComponents); err != nil {
			return nil, fmt.Errorf("parseComponents request: %w", err)
		}
		// Validate that components is an array
		if _, ok := reqComponents.([]interface{}); !ok {
			return nil, errors.New("parseComponets request: components property is not array")
		}
	}

	// If empty, don't step on existing data
	if reqComponents == nil {
		return nil, nil
	}

	// Deserialize the agent's components copy
	var agentComponents interface{}
	if len(agent.Components) > 0 {
		if err := json.Unmarshal(agent.Components, &agentComponents); err != nil {
			return nil, fmt.Errorf("parseComponents local: %w", err)
		}
	}

	var outComponents []byte

	// Compare the deserialized meta structures and return the bytes to update if different
	if !reflect.DeepEqual(reqComponents, agentComponents) {

		zlog.Trace().
			RawJSON("oldComponents", agent.Components).
			RawJSON("newComponents", req.Components).
			Msg("local components data is not equal")

		zlog.Info().
			RawJSON("req.Components", req.Components).
			Msg("applying new components data")

		outComponents = req.Components
	}

	return outComponents, nil
}

func calcPollDuration(zlog zerolog.Logger, cfg *config.Server, setupDuration time.Duration) (time.Duration, time.Duration) {

	pollDuration := cfg.Timeouts.CheckinLongPoll

	// Under heavy load, elastic may take along time to authorize the api key, many seconds to minutes.
	// Short circuit the long poll to take the setup delay into account.  This is particularly necessary
	// in cloud where the proxy will time us out after 30m20s causing unnecessary errors.

	if setupDuration >= pollDuration {
		// We took so long to setup that we need to exit immediately
		pollDuration = time.Millisecond
		zlog.Warn().
			Dur("setupDuration", setupDuration).
			Dur("pollDuration", cfg.Timeouts.CheckinLongPoll).
			Msg("excessive setup duration short cicuit long poll")

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
	if cfg.Timeouts.CheckinJitter != 0 {
		jitter = time.Duration(rand.Int63n(int64(cfg.Timeouts.CheckinJitter))) //nolint:gosec // jitter time does not need to by generated from a crypto secure source
		if jitter < pollDuration {
			pollDuration = pollDuration - jitter
			zlog.Trace().Dur("poll", pollDuration).Msg("Long poll with jitter")
		}
	}

	return pollDuration, jitter
}
