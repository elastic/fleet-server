// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package fleet

import (
	"container/list"
	"context"
	"sync"
	"time"

	"fleet/internal/pkg/saved"

	"github.com/rs/zerolog/log"
)

type BulkActions struct {
	mut   sync.Mutex
	pollQ *list.List
}

type ActionChan chan []Action

type qType struct {
	ch       ActionChan
	agentId  string
	deadline time.Time
}

type ActionSub struct {
	node *list.Element
}

func (as ActionSub) Ch() ActionChan {
	n := as.node.Value.(*qType)
	return n.ch
}

func (as ActionSub) AgentId() string {
	n := as.node.Value.(*qType)
	return n.agentId
}

const (
	kPollQueueDelay = time.Minute * 2 // TODO env
	kMaxTerms       = 65536           // TODO env: see elastic docs on terms query
)

func NewBulkActions() *BulkActions {
	return &BulkActions{
		pollQ: list.New(),
	}
}

func (ba *BulkActions) Subscribe(agentId string) (*ActionSub, error) {

	cbCh := make(chan []Action, 1)

	ba.mut.Lock()
	node := ba.pollQ.PushFront(&qType{
		ch:      cbCh,
		agentId: agentId,
	})
	qLen := ba.pollQ.Len()
	ba.mut.Unlock()

	log.Trace().Str("agentId", agentId).Int("qLen", qLen).Msg("Bulk action Subscribe")

	sub := ActionSub{
		node: node,
	}

	return &sub, nil
}

func (ba *BulkActions) Unsubscribe(sub *ActionSub) error {
	if sub == nil {
		return nil
	}

	ba.mut.Lock()
	ba.pollQ.Remove(sub.node)
	qLen := ba.pollQ.Len()
	ba.mut.Unlock()

	log.Trace().Str("agentId", sub.AgentId()).Int("qLen", qLen).Msg("Bulk action Unsubscribe")
	return nil
}

func (ba *BulkActions) gatherAgents() map[string]ActionChan {
	ba.mut.Lock()
	defer ba.mut.Unlock()

	now := time.Now()
	later := now.Add(kPollQueueDelay)

	// Gather items to check on, requeue for later fire
	agentMap := make(map[string]ActionChan)

	n := ba.pollQ.Front()
	for n != nil {
		next := n.Next()

		q := n.Value.(*qType)
		if q.deadline.Before(now) {
			agentMap[q.agentId] = q.ch
			q.deadline = later
			ba.pollQ.MoveToBack(n)
		}

		n = next
	}

	return agentMap
}

func (ba *BulkActions) processQueue(ctx context.Context, sv saved.CRUD) error {

	agentMap := ba.gatherAgents()

	slices := splitKeysN(agentMap, kMaxTerms)

	for _, agentSlice := range slices {
		//log.Trace().Strs("agentIds", agentSlice).Msg("Bulk action agent list")

		dispatchMap, err := ba.queryES(ctx, sv, agentSlice)

		if err != nil {
			return err
		}

		ba.dispatchActions(dispatchMap, agentMap)
	}

	return nil
}

// O(n)
func splitKeysN(m map[string]ActionChan, max int) [][]string {
	if len(m) == 0 {
		return nil
	}

	var slices [][]string

	s := make([]string, 0, max)
	for k, _ := range m {
		s = append(s, k)
		if len(s) == max {
			slices = append(slices, s)
			s = make([]string, 0, max)
		}
	}

	if len(s) != 0 {
		slices = append(slices, s)
	}

	return slices
}

func (ba *BulkActions) dispatchActions(dispatchMap map[string][]Action, agentMap map[string]ActionChan) {

	for agentId, actionList := range dispatchMap {
		if ch, ok := agentMap[agentId]; ok {
			select {
			case ch <- actionList:
			default:
				log.Info().Str("agentId", agentId).Msg("actionList dropped on full channel")
			}
		}
	}
}

func (ba *BulkActions) queryES(ctx context.Context, sv saved.CRUD, agentIds []string) (map[string][]Action, error) {
	raw, err := agentActionQueryTmpl.RenderOne(kTmplAgentIdField, agentIds)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	hits, err := sv.FindRaw(ctx, raw)
	if err != nil {
		log.Error().
			Dur("rtt", time.Since(start)).
			Int("sz", len(agentIds)).
			Err(err).
			Msg("Fail retrieve actions for agents")
		return nil, err
	}

	log.Debug().
		Dur("rtt", time.Since(start)).
		Int("nHits", len(hits)).
		Int("sz", len(agentIds)).
		Msg("Bulk action find")

	dispatchMap := make(map[string][]Action)

	for _, hit := range hits {
		var action Action
		if err := sv.Decode(hit, &action); err != nil {
			log.Error().
				Err(err).
				Str("id", hit.Id).
				Msg("Fail to decode action")
		} else {
			actionList := append(dispatchMap[action.AgentId], action)
			dispatchMap[action.AgentId] = actionList
		}
	}

	return dispatchMap, err
}

func (ba *BulkActions) Run(ctx context.Context, sv saved.CRUD) error {
	var err error

	queryFreq := time.Second * 10 // TODO env
	tick := time.NewTicker(queryFreq)
	defer tick.Stop()

LOOP:
	for {

		select {
		case <-tick.C:
			if err = ba.processQueue(ctx, sv); err != nil {
				log.Error().Err(err).Msg("Fail dispatchQueue and keep trucking")
				err = nil
			}
		case <-ctx.Done():
			err = ctx.Err()
			break LOOP
		}
	}

	return err
}
