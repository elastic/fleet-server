// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/action"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
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
	ErrNoOutputPerms    = errors.New("output permission sections not found")
	ErrNoPolicyOutput   = errors.New("output section not found")
	ErrFailInjectApiKey = errors.New("fail inject api key")
)

const kEncodingGzip = "gzip"

func (rt Router) handleCheckin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	id := ps.ByName("id")
	err := rt.ct._handleCheckin(w, r, id, rt.bulker)

	if err != nil {
		code, lvl := cntCheckin.IncError(err)

		// Log this as warn for visibility that limit has been reached.
		// This allows customers to tune the configuration on detection of threshold.
		if err == limit.ErrMaxLimit {
			lvl = zerolog.WarnLevel
		}

		log.WithLevel(lvl).
			Err(err).
			Str("id", id).
			Int("code", code).
			Msg("fail checkin")

		http.Error(w, "", code)
	}
}

type CheckinT struct {
	verCon version.Constraints
	cfg    *config.Server
	cache  cache.Cache
	bc     *BulkCheckin
	pm     policy.Monitor
	gcp    monitor.GlobalCheckpointProvider
	ad     *action.Dispatcher
	tr     *action.TokenResolver
	bulker bulk.Bulk
	limit  *limit.Limiter
}

func NewCheckinT(
	verCon version.Constraints,
	cfg *config.Server,
	c cache.Cache,
	bc *BulkCheckin,
	pm policy.Monitor,
	gcp monitor.GlobalCheckpointProvider,
	ad *action.Dispatcher,
	tr *action.TokenResolver,
	bulker bulk.Bulk,
) *CheckinT {

	log.Info().
		Interface("limits", cfg.Limits.CheckinLimit).
		Dur("long_poll_timeout", cfg.Timeouts.CheckinLongPoll).
		Dur("long_poll_timestamp", cfg.Timeouts.CheckinTimestamp).
		Msg("Checkin install limits")

	ct := &CheckinT{
		verCon: verCon,
		cfg:    cfg,
		cache:  c,
		bc:     bc,
		pm:     pm,
		gcp:    gcp,
		ad:     ad,
		tr:     tr,
		limit:  limit.NewLimiter(&cfg.Limits.CheckinLimit),
		bulker: bulker,
	}

	return ct
}

func (ct *CheckinT) _handleCheckin(w http.ResponseWriter, r *http.Request, id string, bulker bulk.Bulk) error {

	limitF, err := ct.limit.Acquire()
	if err != nil {
		return err
	}
	defer limitF()

	agent, err := authAgent(r, id, ct.bulker, ct.cache)

	if err != nil {
		return err
	}

	err = validateUserAgent(r, ct.verCon)
	if err != nil {
		return err
	}

	// Metrics; serenity now.
	dfunc := cntCheckin.IncStart()
	defer dfunc()

	ctx := r.Context()

	// Interpret request; TODO: defend overflow, slow roll
	readCounter := datacounter.NewReaderCounter(r.Body)

	var req CheckinRequest
	decoder := json.NewDecoder(readCounter)
	if err := decoder.Decode(&req); err != nil {
		return err
	}

	cntCheckin.bodyIn.Add(readCounter.Count())

	// Compare local_metadata content and update if different
	fields, err := parseMeta(agent, &req)
	if err != nil {
		return err
	}

	// Resolve AckToken from request, fallback on the agent record
	seqno, err := ct.resolveSeqNo(ctx, req, agent)
	if err != nil {
		return err
	}

	// Subsribe to actions dispatcher
	aSub := ct.ad.Subscribe(agent.Id, seqno)
	defer ct.ad.Unsubscribe(aSub)
	actCh := aSub.Ch()

	// Subscribe to policy manager for changes on PolicyId > policyRev
	sub, err := ct.pm.Subscribe(agent.Id, agent.PolicyId, agent.PolicyRevisionIdx, agent.PolicyCoordinatorIdx)
	if err != nil {
		return err
	}
	defer ct.pm.Unsubscribe(sub)

	// Update check-in timestamp on timeout
	tick := time.NewTicker(ct.cfg.Timeouts.CheckinTimestamp)
	defer tick.Stop()

	// Chill out for for a bit. Long poll.
	longPoll := time.NewTicker(ct.cfg.Timeouts.CheckinLongPoll)
	defer longPoll.Stop()

	// Intial update on checkin, and any user fields that might have changed
	ct.bc.CheckIn(agent.Id, fields, seqno)

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
	actions, ackToken = convertActions(agent.Id, pendingActions)

	if len(actions) == 0 {
	LOOP:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case acdocs := <-actCh:
				var acs []ActionResp
				acs, ackToken = convertActions(agent.Id, acdocs)
				actions = append(actions, acs...)
				break LOOP
			case policy := <-sub.Output():
				actionResp, err := processPolicy(ctx, bulker, agent.Id, policy)
				if err != nil {
					return err
				}
				actions = append(actions, *actionResp)
				break LOOP
			case <-longPoll.C:
				log.Trace().Msg("fire long poll")
				break LOOP
			case <-tick.C:
				ct.bc.CheckIn(agent.Id, nil, seqno)
			}
		}
	}

	resp := CheckinResponse{
		AckToken: ackToken,
		Action:   "checkin",
		Actions:  actions,
	}

	return ct.writeResponse(w, r, resp)
}

func (ct *CheckinT) writeResponse(w http.ResponseWriter, r *http.Request, resp CheckinResponse) error {

	payload, err := json.Marshal(&resp)
	if err != nil {
		return err
	}

	compressionLevel := ct.cfg.CompressionLevel
	compressThreshold := ct.cfg.CompressionThresh

	if len(payload) > compressThreshold && compressionLevel != flate.NoCompression && acceptsEncoding(r, kEncodingGzip) {

		wrCounter := datacounter.NewWriterCounter(w)

		zipper, err := gzip.NewWriterLevel(wrCounter, compressionLevel)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Encoding", kEncodingGzip)

		if _, err = zipper.Write(payload); err != nil {
			return err
		}

		err = zipper.Close()

		cntCheckin.bodyOut.Add(wrCounter.Count())

		log.Trace().
			Err(err).
			Int("lvl", compressionLevel).
			Int("srcSz", len(payload)).
			Uint64("dstSz", wrCounter.Count()).
			Msg("compressing checkin response")
	} else {
		var nWritten int
		nWritten, err = w.Write(payload)
		cntCheckin.bodyOut.Add(uint64(nWritten))
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
func (ct *CheckinT) resolveSeqNo(ctx context.Context, req CheckinRequest, agent *model.Agent) (seqno sqn.SeqNo, err error) {
	// Resolve AckToken from request, fallback on the agent record
	ackToken := req.AckToken
	seqno = agent.ActionSeqNo

	if ct.tr != nil && ackToken != "" {
		var sn int64
		sn, err = ct.tr.Resolve(ctx, ackToken)
		if err != nil {
			if errors.Is(err, dl.ErrNotFound) {
				log.Debug().Str("token", ackToken).Str("agent_id", agent.Id).Msg("revision token not found")
				err = nil
			} else {
				return
			}
		}
		seqno = []int64{sn}
	}
	return seqno, nil
}

func (ct *CheckinT) fetchAgentPendingActions(ctx context.Context, seqno sqn.SeqNo, agentId string) ([]model.Action, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	return dl.FindActions(ctx, ct.bulker, dl.QueryAgentActions, map[string]interface{}{
		dl.FieldSeqNo:      seqno.Value(),
		dl.FieldMaxSeqNo:   ct.gcp.GetCheckpoint().Value(),
		dl.FieldExpiration: now,
		dl.FieldAgents:     []string{agentId},
	})
}

func convertActions(agentId string, actions []model.Action) ([]ActionResp, string) {
	var ackToken string
	sz := len(actions)

	respList := make([]ActionResp, 0, sz)
	for _, action := range actions {
		respList = append(respList, ActionResp{
			AgentId:   agentId,
			CreatedAt: action.Timestamp,
			Data:      action.Data,
			Id:        action.ActionId,
			Type:      action.Type,
			InputType: action.InputType,
		})
	}

	if sz > 0 {
		ackToken = actions[sz-1].Id
	}

	return respList, ackToken
}

// A new policy exists for this agent.  Perform the following:
//  - Generate and update default ApiKey if roles have changed.
//  - Rewrite the policy for delivery to the agent injecting the key material.
//
func processPolicy(ctx context.Context, bulker bulk.Bulk, agentId string, pp *policy.ParsedPolicy) (*ActionResp, error) {

	zlog := log.With().
		Str("ctx", "processPolicy").
		Str("agentId", agentId).
		Str("policyId", pp.Policy.PolicyId).
		Logger()

	// The parsed policy object contains a map of name->role with a precalculated sha2.
	defaultRole, ok := pp.Roles[policy.DefaultOutputName]
	if !ok {
		zlog.Error().Str("name", policy.DefaultOutputName).Msg("policy does not contain required output permission section")
		return nil, ErrNoOutputPerms
	}

	// Repull and decode the agent object.  Do not trust the cache.
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByID, dl.FieldId, agentId)
	if err != nil {
		zlog.Error().Err(err).Msg("fail find agent record")
		return nil, err
	}

	// Determine whether we need to generate a default output ApiKey.
	// This is accomplished by comparing the sha2 hash stored in the agent
	// record with the precalculated sha2 hash of the role.
	needKey := true
	switch {
	case agent.DefaultApiKey == "":
		zlog.Debug().Msg("must generate api key as default API key is not present")
	case defaultRole.Sha2 != agent.PolicyOutputPermissionsHash:
		zlog.Debug().Msg("must generate api key as policy output permissions changed")
	default:
		needKey = false
		zlog.Debug().Msg("policy output permissions are the same")
	}

	if needKey {
		zlog.Debug().
			RawJSON("roles", defaultRole.Raw).
			Str("oldHash", agent.PolicyOutputPermissionsHash).
			Str("newHash", defaultRole.Sha2).
			Msg("Generating a new API key")

		defaultOutputApiKey, err := generateOutputApiKey(ctx, bulker.Client(), agent.Id, policy.DefaultOutputName, defaultRole.Raw)
		if err != nil {
			zlog.Error().Err(err).Msg("fail generate output key")
			return nil, err
		}

		zlog.Info().
			Str("hash", defaultRole.Sha2).
			Str("apiKeyId", defaultOutputApiKey.Id).
			Msg("Updating agent record to pick up default output key.")

		fields := map[string]interface{}{
			dl.FieldDefaultApiKey:               defaultOutputApiKey.Agent(),
			dl.FieldDefaultApiKeyId:             defaultOutputApiKey.Id,
			dl.FieldPolicyOutputPermissionsHash: defaultRole.Sha2,
		}

		body, err := json.Marshal(map[string]interface{}{
			"doc": fields,
		})
		if err != nil {
			return nil, err
		}

		if err = bulker.Update(ctx, dl.FleetAgents, agent.Id, body); err != nil {
			zlog.Error().Err(err).Msg("fail update agent record")
			return nil, err
		}
		agent.DefaultApiKey = defaultOutputApiKey.Agent()
	}

	rewrittenPolicy, err := rewritePolicy(pp, agent.DefaultApiKey)
	if err != nil {
		zlog.Error().Err(err).Msg("fail rewrite policy")
		return nil, err
	}

	r := policy.RevisionFromPolicy(pp.Policy)
	resp := ActionResp{
		AgentId:   agent.Id,
		CreatedAt: pp.Policy.Timestamp,
		Data:      rewrittenPolicy,
		Id:        r.String(),
		Type:      TypePolicyChange,
	}

	return &resp, nil
}

// Return Serializable policy injecting the apikey into the output field.
// This avoids reallocation of each section of the policy by duping
// the map object and only replacing the targeted section.
func rewritePolicy(pp *policy.ParsedPolicy, apiKey string) (interface{}, error) {

	// Parse the outputs maps in order to inject the api key
	const outputsProperty = "outputs"
	outputs, err := smap.Parse(pp.Fields[outputsProperty])
	if err != nil {
		return nil, err
	}

	if outputs == nil {
		return nil, ErrNoPolicyOutput
	}

	if ok := setMapObj(outputs, apiKey, "default", "api_key"); !ok {
		return nil, ErrFailInjectApiKey
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

	fields[outputsProperty] = json.RawMessage(outputRaw)

	return struct {
		Policy map[string]json.RawMessage `json:"policy"`
	}{fields}, nil
}

func setMapObj(obj map[string]interface{}, val interface{}, keys ...string) bool {
	if len(keys) == 0 {
		return false
	}

	for _, k := range keys[:len(keys)-1] {
		v, ok := obj[k]
		if !ok {
			return false
		}

		obj, ok = v.(map[string]interface{})
		if !ok {
			return false
		}
	}

	k := keys[len(keys)-1]
	obj[k] = val

	return true
}

func findAgentByApiKeyId(ctx context.Context, bulker bulk.Bulk, id string) (*model.Agent, error) {
	agent, err := dl.FindAgent(ctx, bulker, dl.QueryAgentByAssessAPIKeyID, dl.FieldAccessAPIKeyID, id)
	if err != nil && errors.Is(err, dl.ErrNotFound) {
		err = ErrAgentNotFound
	}
	return &agent, err
}

// parseMeta compares the agent and the request local_metadata content
// and returns fields to update the agent record or nil
func parseMeta(agent *model.Agent, req *CheckinRequest) (fields Fields, err error) {
	// Quick comparison first
	if bytes.Equal(req.LocalMeta, agent.LocalMetadata) {
		log.Trace().Msg("quick comparing local metadata is equal")
		return nil, nil
	}

	// Compare local_metadata content and update if different
	var reqLocalMeta Fields
	var agentLocalMeta Fields
	err = json.Unmarshal(req.LocalMeta, &reqLocalMeta)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(agent.LocalMetadata, &agentLocalMeta)
	if err != nil {
		return nil, err
	}

	if reqLocalMeta != nil && !reflect.DeepEqual(reqLocalMeta, agentLocalMeta) {
		log.Trace().RawJSON("oldLocalMeta", agent.LocalMetadata).RawJSON("newLocalMeta", req.LocalMeta).Msg("local metadata not equal")
		log.Info().RawJSON("req.LocalMeta", req.LocalMeta).Msg("applying new local metadata")
		fields = map[string]interface{}{
			FieldLocalMetadata: req.LocalMeta,
		}
	}
	return fields, nil
}
