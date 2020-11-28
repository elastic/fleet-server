package fleet

import (
	"context"
	"encoding/json"
	"fleet/internal/pkg/seqno"
	"sync"

	"github.com/rs/zerolog/log"
)

// TODO: better name
type ActionX struct {
	Id          string          `json:"id"`
	Token       string          `json:"token"`
	SeqNo       uint64          `json:"seqno"`
	Type        string          `json:"type"`
	Agents      []string        `json:"agents"`
	Application string          `json:"application"`
	Data        json.RawMessage `json:"data"`
	CreatedAt   string          `json:"@timestamp"`
	Expiration  string          `json:"expiration"`
}

type ActionSubX struct {
	agentId string
	seqNo   int64
	ch      chan []ActionX
}

func (as ActionSubX) Ch() chan []ActionX {
	return as.ch
}

type ActionDispatcher struct {
	am *seqno.Monitor

	mx   sync.RWMutex
	subs map[string]ActionSubX
}

func NewActionDispatcher(am *seqno.Monitor) *ActionDispatcher {
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

func (ad *ActionDispatcher) process(ctx context.Context, hits []seqno.Hit) {
	// Parse hits into map of agent -> actions
	// Actions are ordered by sequence

	var (
		actions []ActionX
	)

	for _, hit := range hits {
		log.Debug().Str("id", hit.ID).Uint64("seqNo", hit.SeqNo).Str("source", string(hit.Source)).Msg("New Action")

		var action ActionX
		err := json.Unmarshal(hit.Source, &action)
		if err != nil {
			log.Error().Err(err).Msg("Failed to parse the action details")
			continue
		}

		// Elasticsearch _id serves as a token for the action _seq_no
		action.Token = hit.ID
		action.SeqNo = hit.SeqNo
		actions = append(actions, action)
	}

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
		log.Info().Str("agent_id", agentId).Msg("Agent is not currently connected. Not dispatching actions.")
		return
	}
	select {
	case sub.Ch() <- actions:
	case <-ctx.Done():
	}
}
