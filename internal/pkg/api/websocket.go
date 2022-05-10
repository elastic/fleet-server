// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/action"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"

	"github.com/blakerouse/concurrent-websocket"
	"github.com/hashicorp/go-version"
	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func (rt Router) handleWS(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	id := ps.ByName("id")

	reqID := r.Header.Get(logger.HeaderRequestID)

	zlog := log.With().
		Str(LogAgentID, id).
		Str(ECSHTTPRequestID, reqID).
		Logger()

	err := rt.ws.connect(&zlog, w, r, id)

	if err != nil {
		cntWebsocket.IncError(err)
		resp := NewHTTPErrResp(err)

		// Log this as warn for visibility that limit has been reached.
		// This allows customers to tune the configuration on detection of threshold.
		if errors.Is(err, limit.ErrMaxLimit) {
			resp.Level = zerolog.WarnLevel
		}

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

type agentConn struct {
	ctx context.Context
	conn *websocket.Channel
	zlog zerolog.Logger
	start time.Time
	agent *model.Agent
	ver string
	canceller context.CancelFunc
	cancelWait chan struct{}
}

type AgentWS struct {
	verCon version.Constraints
	cfg    *config.Server
	cache  cache.Cache
	bc     *checkin.Bulk
	pm     policy.Monitor
	gcp    monitor.GlobalCheckpointProvider
	ad     *action.Dispatcher
	tr     *action.TokenResolver
	ack    *AckT
	bulker bulk.Bulk
	limit  *limit.Limiter
	ws *websocket.Handler
	conns map[*websocket.Channel]agentConn
	connsMux sync.RWMutex
}

func NewAgentWS(
	verCon version.Constraints,
	cfg *config.Server,
	c cache.Cache,
	bc *checkin.Bulk,
	pm policy.Monitor,
	gcp monitor.GlobalCheckpointProvider,
	ad *action.Dispatcher,
	tr *action.TokenResolver,
	ack *AckT,
	bulker bulk.Bulk,
) (*AgentWS, error) {

	log.Info().
		Interface("limits", cfg.Limits.CheckinLimit).
		Int("websocket_read_concurrency", cfg.Limits.CheckinLimit.ReadConcurrency).
		Int("websocket_write_concurrency", cfg.Limits.CheckinLimit.WriteConcurrency).
		Dur("websocket_jitter", cfg.Timeouts.CheckinJitter).
		Msg("agent websocket install limits")

	ct := &AgentWS{
		verCon: verCon,
		cfg:    cfg,
		cache:  c,
		bc:     bc,
		pm:     pm,
		gcp:    gcp,
		ad:     ad,
		tr:     tr,
		ack:    ack,
		limit:  limit.NewLimiter(&cfg.Limits.CheckinLimit.Limit),
		bulker: bulker,
	}

	ws, err := websocket.NewHandler(ct.callback, cfg.Limits.CheckinLimit.ReadConcurrency, cfg.Limits.CheckinLimit.WriteConcurrency)
	if err != nil {
		return nil, err
	}
	ct.ws = ws
	ct.conns = make(map[*websocket.Channel]agentConn)

	return ct, nil
}

func (ct *AgentWS) connect(zlog *zerolog.Logger, w http.ResponseWriter, r *http.Request, id string) error {

	start := time.Now()

	limitF, err := ct.limit.Acquire()
	if err != nil {
		return err
	}

	agent, err := authAgent(r, &id, ct.bulker, ct.cache)

	if err != nil {
		limitF()
		return err
	}

	// Pointer is passed in to allow UpdateContext by child function
	zlog.UpdateContext(func(ctx zerolog.Context) zerolog.Context {
		return ctx.Str(LogAccessAPIKeyID, agent.AccessAPIKeyID)
	})

	ver, err := validateUserAgent(*zlog, r, ct.verCon)
	if err != nil {
		limitF()
		return err
	}

	// Safely check if the agent version is different, return empty string otherwise
	newVer := agent.CheckDifferentVersion(ver)

	// Metrics; serenity now.
	dfunc := cntWebsocket.IncStart()

	// Create the websocket channel.
	ctx, canceller := context.WithCancel(context.Background())
	conn, err := ct.ws.CreateChannel(w, r)
	if err != nil {
		dfunc()
		limitF()
		return err
	}
	conn.SetOnClose(func() {
		ct.connsMux.Lock()
		defer ct.connsMux.Unlock()
		state, ok := ct.conns[conn]
		if ok && state.canceller != nil {
			state.canceller()
		}
		delete(ct.conns, conn)
		canceller()
		dfunc()
		limitF()
	})
	ct.connsMux.Lock()
	defer ct.connsMux.Unlock()
	ct.conns[conn] = agentConn{
		ctx: ctx,
		conn: conn,
		zlog:  *zlog,
		start: start,
		agent: agent,
		ver:   newVer,
	}

	return nil
}

func (ct *AgentWS) callback(c *websocket.Channel, op websocket.OpCode, data []byte) {
	ct.connsMux.RLock()
	conn, ok := ct.conns[c]
	ct.connsMux.RUnlock()
	if !ok {
		// no recorded connection; disconnect
		c.Close()
		return
	}

	switch op {
	case websocket.OpText:
		break
	default:
		// unsupported opcode
		conn.zlog.Error().Msgf("client send unknown opcode: %d", op)
		c.Close()
		return
	}

	var req WebsocketRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&req); err != nil {
		conn.zlog.Error().Err(err).Msg("failed to decode message")
		c.Close()
		return
	}

	cntWebsocket.bodyIn.Add(uint64(len(data)))

	if req.Checkin != nil {
		if err := ct.handleCheckin(conn.ctx, &conn, *req.Checkin); err != nil {
			conn.zlog.Error().Err(err).Msg("failed to handle checkin")
			c.Close()
			return
		}
	} else if req.Ack != nil {
		if err := ct.handleAck(conn.ctx, &conn, *req.Ack); err != nil {
			conn.zlog.Error().Err(err).Msg("failed to handle ack")
			c.Close()
			return
		}
	} else {
		conn.zlog.Error().Msg("message missing either checkin or ack")
		c.Close()
	}
}

func (ct *AgentWS) handleCheckin(ctx context.Context, conn *agentConn, req CheckinRequest) error {
	// Previous checkin worker gets cancelled when this checkin happens
	if conn.canceller != nil {
		conn.canceller()
		conn.canceller = nil
	}
	if conn.cancelWait != nil {
		<-conn.cancelWait
		conn.cancelWait = nil
	}

	// Compare local_metadata content and update if different
	rawMeta, err := parseMeta(conn.zlog, conn.agent, &req)
	if err != nil {
		return err
	}

	// Resolve AckToken from request, fallback on the agent record
	seqno, err := resolveSeqNo(ctx, conn.zlog, ct.tr, req, conn.agent)
	if err != nil {
		return err
	}

	// Perform the work for check-in
	cancelWait := make(chan struct{})
	workContext, canceller := context.WithCancel(ctx)
	go func(ctx context.Context) {
		defer close(cancelWait)

		// Subscribe to actions dispatcher
		aSub := ct.ad.Subscribe(conn.agent.Id, seqno)
		defer ct.ad.Unsubscribe(aSub)
		actCh := aSub.Ch()

		// Subscribe to policy manager for changes on PolicyId > policyRev
		sub, err := ct.pm.Subscribe(conn.agent.Id, conn.agent.PolicyID, conn.agent.PolicyRevisionIdx, conn.agent.PolicyCoordinatorIdx)
		if err != nil {
			conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Str("policy_id", conn.agent.PolicyID).Msg("unable to subscribe to policy changes")
		}
		defer func() {
			err := ct.pm.Unsubscribe(sub)
			if err != nil {
				conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Str("policy_id", conn.agent.PolicyID).Msg("unable to unsubscribe from policy")
			}
		}()

		// Update check-in timestamp on timeout
		tick := time.NewTicker(ct.cfg.Timeouts.CheckinTimestamp)
		defer tick.Stop()

		conn.zlog.Debug().
			Str("status", req.Status).
			Str("seqNo", seqno.String()).
			Msg("checkin websocket message received")

		// Initial update on checkin, and any user fields that might have changed
		err = ct.bc.CheckIn(conn.agent.Id, req.Status, rawMeta, seqno, conn.ver)
		if err != nil {
			conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Msg("checkin failed")
		}

		// Check/send agent pending actions first
		pendingActions, err := fetchAgentPendingActions(ctx, ct.bulker, seqno, ct.gcp, conn.agent.Id)
		if err != nil {
			conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Msg("unable to fetch pending actions")
		}
		actions, ackToken := convertActions(conn.agent.Id, pendingActions)
		err = writeWSCheckinResponse(conn, ackToken, actions)
		if err != nil {
			conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Msg("unable to send pending actions")
		}

		for {
			select {
			case <-ctx.Done():
				return
			case acdocs := <-actCh:
				actions, ackToken := convertActions(conn.agent.Id, acdocs)
				err = writeWSCheckinResponse(conn, ackToken, actions)
				if err != nil {
					conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Msg("unable to send pending actions")
				}
			case policy := <-sub.Output():
				actionResp, err := processPolicy(ctx, conn.zlog, ct.bulker, conn.agent.Id, policy)
				if err != nil {
					conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Msg("failed to process policy change")
				} else {
					err = writeWSCheckinResponse(conn, ackToken, []ActionResp{actionResp})
					if err != nil {
						conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Msg("unable to send pending actions")
					}
				}
			case <-tick.C:
				err := ct.bc.CheckIn(conn.agent.Id, req.Status, nil, nil, conn.ver)
				if err != nil {
					conn.zlog.Error().Err(err).Str("agent_id", conn.agent.Id).Msg("checkin failed")
				}
			}
		}
	}(workContext)
	conn.cancelWait = cancelWait
	conn.canceller = canceller
	return nil
}

func (ct *AgentWS) handleAck(ctx context.Context, conn *agentConn, req AckRequest) error {
	// Metrics; serenity now.
	dfunc := cntAcks.IncStart()
	defer dfunc()

	zlog := conn.zlog.With().Int("nEvents", len(req.Events)).Logger()

	resp, err := ct.ack.handleAckEvents(ctx, zlog, conn.agent, req.Events)
	if err != nil {
		return err
	}

	return writeWSAckResponse(conn, resp)
}

func writeWSResponse(conn *agentConn, resp WebsocketResponse) error {
	payload, err := json.Marshal(&resp)
	if err != nil {
		return errors.Wrap(err, "writeWSResponse marshal")
	}

	conn.conn.Send(websocket.OpText, payload)
	return nil
}

func writeWSCheckinResponse(conn *agentConn, ackToken string, actions []ActionResp) error {
	if len(actions) > 0 {
		for _, action := range actions {
			conn.zlog.Info().
				Str("ackToken", ackToken).
				Str("createdAt", action.CreatedAt).
				Str("id", action.ID).
				Str("type", action.Type).
				Str("inputType", action.InputType).
				Int64("timeout", action.Timeout).
				Msg("Action delivered to agent on checkin")
		}

		checkin := CheckinResponse{
			AckToken: ackToken,
			Action:   "checkin",
			Actions:  actions,
		}
		resp := WebsocketResponse{
			Checkin: &checkin,
		}
		return writeWSResponse(conn, resp)
	}
	return nil
}

func writeWSAckResponse(conn *agentConn, ack AckResponse) error {
	resp := WebsocketResponse{
		Ack: &ack,
	}
	return writeWSResponse(conn, resp)
}
