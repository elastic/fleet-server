package fleet

import (
	"context"
	"fleet/internal/pkg/action"
	"fleet/internal/pkg/esutil"
	"sync"

	"github.com/rs/zerolog/log"
)

type ActionX = action.ActionX

type ActionSubX struct {
	agentId string
	seqNo   int64
	ch      chan []ActionX
}

func (as ActionSubX) Ch() chan []ActionX {
	return as.ch
}

type ActionDispatcher struct {
	am *action.Monitor

	mx   sync.RWMutex
	subs map[string]ActionSubX
}

func NewActionDispatcher(am *action.Monitor) *ActionDispatcher {
	return &ActionDispatcher{
		am:   am,
		subs: make(map[string]ActionSubX),
	}
}

func (ad *ActionDispatcher) Run(ctx context.Context) (err error) {
	for {
		select {
		case <-ctx.Done():
			return
		case hits := <-ad.am.Output():
			ad.process(ctx, hits)
		}
	}
}

func (ad *ActionDispatcher) Subscribe(agentId string, seqNo int64) *ActionSubX {
	cbCh := make(chan []ActionX, 1)

	sub := ActionSubX{
		agentId: agentId,
		seqNo:   seqNo,
		ch:      cbCh,
	}

	ad.mx.Lock()
	ad.subs[agentId] = sub
	sz := len(ad.subs)
	ad.mx.Unlock()

	log.Trace().Str("agentId", agentId).Int("sz", sz).Msg("Action dispatcher subscribe")

	return &sub
}

func (ad *ActionDispatcher) Unsubscribe(sub *ActionSubX) {
	if sub == nil {
		return
	}

	ad.mx.Lock()
	delete(ad.subs, sub.agentId)
	sz := len(ad.subs)
	ad.mx.Unlock()

	log.Debug().Str("agentId", sub.agentId).Int("sz", sz).Msg("Action dispatcher unsubscribe")
}

func (ad *ActionDispatcher) process(ctx context.Context, hits []esutil.Hit) {
	// Parse hits into map of agent -> actions
	// Actions are ordered by sequence

	actions := action.HitsToActions(hits)

	agentActions := make(map[string][]ActionX)
	for _, action := range actions {
		for _, agentId := range action.Agents {
			arr := agentActions[agentId]
			arr = append(arr, action)
			agentActions[agentId] = arr
		}
	}

	// TODO: revisit actions rollout
	for agentId, actions := range agentActions {
		ad.dispatch(ctx, agentId, actions)
	}
}

func (ad *ActionDispatcher) getSub(agentId string) (ActionSubX, bool) {
	ad.mx.RLock()
	sub, ok := ad.subs[agentId]
	ad.mx.RUnlock()
	return sub, ok
}

func (ad *ActionDispatcher) dispatch(ctx context.Context, agentId string, actions []ActionX) {
	sub, ok := ad.getSub(agentId)
	if !ok {
		log.Debug().Str("agent_id", agentId).Msg("Agent is not currently connected. Not dispatching actions.")
		return
	}
	select {
	case sub.Ch() <- actions:
	case <-ctx.Done():
	}
}
