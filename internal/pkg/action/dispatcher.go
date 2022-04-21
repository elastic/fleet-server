// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package action

import (
	"context"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"

	"github.com/rs/zerolog/log"
)

type Sub struct {
	agentID string
	seqNo   sqn.SeqNo
	ch      chan []model.Action
}

func (s Sub) Ch() chan []model.Action {
	return s.ch
}

type Dispatcher struct {
	am monitor.SimpleMonitor

	mx   sync.RWMutex
	subs map[string]Sub
}

func NewDispatcher(am monitor.SimpleMonitor) *Dispatcher {
	return &Dispatcher{
		am:   am,
		subs: make(map[string]Sub),
	}
}

func (d *Dispatcher) Run(ctx context.Context) (err error) {
	for {
		select {
		case <-ctx.Done():
			return
		case hits := <-d.am.Output():
			d.process(ctx, hits)
		}
	}
}

func (d *Dispatcher) Subscribe(agentID string, seqNo sqn.SeqNo) *Sub {
	cbCh := make(chan []model.Action, 1)

	sub := Sub{
		agentID: agentID,
		seqNo:   seqNo,
		ch:      cbCh,
	}

	d.mx.Lock()
	d.subs[agentID] = sub
	sz := len(d.subs)
	d.mx.Unlock()

	log.Trace().Str(logger.AgentId, agentID).Int("sz", sz).Msg("Subscribed to action dispatcher")

	return &sub
}

func (d *Dispatcher) Unsubscribe(sub *Sub) {
	if sub == nil {
		return
	}

	d.mx.Lock()
	delete(d.subs, sub.agentID)
	sz := len(d.subs)
	d.mx.Unlock()

	log.Trace().Str(logger.AgentId, sub.agentID).Int("sz", sz).Msg("Unsubscribed from action dispatcher")
}

func (d *Dispatcher) process(ctx context.Context, hits []es.HitT) {
	// Parse hits into map of agent -> actions
	// Actions are ordered by sequence

	agentActions := make(map[string][]model.Action)
	for _, hit := range hits {
		var action model.Action
		err := hit.Unmarshal(&action)
		if err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal action document")
			break
		}
		numAgents := len(action.Agents)
		for i, agentID := range action.Agents {
			arr := agentActions[agentID]
			actionNoAgents := action
			actionNoAgents.StartTime = offsetStartTime(action.StartTime, action.Expiration, action.MinimumExecutionDuration, i, numAgents)
			actionNoAgents.Agents = nil
			arr = append(arr, actionNoAgents)
			agentActions[agentID] = arr
		}
	}

	for agentID, actions := range agentActions {
		d.dispatch(ctx, agentID, actions)
	}
}

// offsetStartTime will return a new start time between start:end-dur based on index i and the total number of agents
// An empty string will be returned if start or exp are empty or if there is an error parsing inputs
// As we expect i < total  the latest return time will always be < exp-dur
func offsetStartTime(start, exp, dur string, i, total int) string {
	if start == "" || exp == "" {
		return ""
	}
	startTS, err := time.Parse(time.RFC3339, start) // TODO what format does a date-time string use?
	if err != nil {
		log.Error().Err(err).Msg("unable to parse start_time string")
		return ""
	}
	expTS, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		log.Error().Err(err).Msg("unable to parse expiration string")
		return ""
	}
	var d time.Duration
	if dur != "" {
		d, err = time.ParseDuration(dur)
		if err != nil {
			log.Error().Err(err).Msg("unable to parse minimum_execution_period string")
			return ""
		}
	}
	d = expTS.Add(-1 * d).Sub(startTS)                                   // the valid scheduling range is: d = exp - dur - start
	startTS = startTS.Add((d * time.Duration(i)) / time.Duration(total)) // adjust start to a position within the range
	return startTS.Format(time.RFC3339)
}

func (d *Dispatcher) getSub(agentID string) (Sub, bool) {
	d.mx.RLock()
	sub, ok := d.subs[agentID]
	d.mx.RUnlock()
	return sub, ok
}

func (d *Dispatcher) dispatch(_ context.Context, agentID string, acdocs []model.Action) {
	sub, ok := d.getSub(agentID)
	if !ok {
		log.Debug().Str(logger.AgentId, agentID).Msg("Agent is not currently connected. Not dispatching actions.")
		return
	}
	select {
	case sub.Ch() <- acdocs:
	default:
		// This prevents action dispatch blocking when the agent subscription channel is full
		// in the case when the agent request loop received the actions on long poll but didn't unsubscribe
		// from the dispatcher.
		// It is safe to drop them since the agent already has actions and will come around on the next check-in to pick up these new actions.
	}
}
