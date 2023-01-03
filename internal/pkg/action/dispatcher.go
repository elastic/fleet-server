// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package action is used to dispatch actions read from elasticsearch to elastic-agents
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

// Sub is an action subscription that will give a single agent all of it's actions.
type Sub struct {
	agentID string
	seqNo   sqn.SeqNo
	ch      chan []model.Action
}

// Ch returns the emitter channel for actions.
func (s Sub) Ch() chan []model.Action {
	return s.ch
}

// Dispatcher tracks agent subscriptions and emits actions to the subscriptions.
type Dispatcher struct {
	am monitor.SimpleMonitor

	mx   sync.RWMutex
	subs map[string]Sub
}

// NewDispatcher creates a Dispatcher using the provided monitor.
func NewDispatcher(am monitor.SimpleMonitor) *Dispatcher {
	return &Dispatcher{
		am:   am,
		subs: make(map[string]Sub),
	}
}

// Run starts the Dispatcher.
// After the Dispatcher is started subscriptions may receive actions.
// Subscribe may be called before or after Run.
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

// Subscribe generates a new subscription with the Dispatcher using the provided agentID and seqNo.
// There is no check to ensure that the agentID has not been used; using the same one twice results in undefined behaviour.
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

	log.Trace().Str(logger.AgentID, agentID).Int("sz", sz).Msg("Subscribed to action dispatcher")

	return &sub
}

// Unsubscribe removes the given subscription from the dispatcher.
// Note that the channel sub.Ch() provides is not closed in this event.
func (d *Dispatcher) Unsubscribe(sub *Sub) {
	if sub == nil {
		return
	}

	d.mx.Lock()
	delete(d.subs, sub.agentID)
	sz := len(d.subs)
	d.mx.Unlock()

	log.Trace().Str(logger.AgentID, sub.agentID).Int("sz", sz).Msg("Unsubscribed from action dispatcher")
}

// process gathers actions from the monitor and dispatches them to the corresponding subscriptions.
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
			actionNoAgents.StartTime = offsetStartTime(action.StartTime, action.RolloutDurationSeconds, i, numAgents)
			actionNoAgents.Agents = nil
			arr = append(arr, actionNoAgents)
			agentActions[agentID] = arr
		}
	}

	for agentID, actions := range agentActions {
		d.dispatch(ctx, agentID, actions)
	}
}

// offsetStartTime will return a new start time between start:start+dur based on index i and the total number of agents
// As we expect i < total  the latest return time will always be < start+dur
func offsetStartTime(start string, dur int64, i, total int) string {

	if start == "" {
		return ""
	}
	startTS, err := time.Parse(time.RFC3339, start)
	if err != nil {
		log.Error().Err(err).Msg("unable to parse start_time string")
		return ""
	}
	d := time.Second * time.Duration(dur)
	startTS = startTS.Add((d * time.Duration(i)) / time.Duration(total)) // adjust start to a position within the range
	return startTS.Format(time.RFC3339)
}

// getSub returns the subscription (if any) for the specified agentID.
func (d *Dispatcher) getSub(agentID string) (Sub, bool) {
	d.mx.RLock()
	sub, ok := d.subs[agentID]
	d.mx.RUnlock()
	return sub, ok
}

// dispatch passes the actions into the subscription channel as a non-blocking operation.
// It may drop actions that will be re-sent to the agent on its next check in.
func (d *Dispatcher) dispatch(_ context.Context, agentID string, acdocs []model.Action) {
	sub, ok := d.getSub(agentID)
	if !ok {
		log.Debug().Str(logger.AgentID, agentID).Msg("Agent is not currently connected. Not dispatching actions.")
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
