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
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"fleet/internal/pkg/saved"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

var ErrEventAgentIdMismatch = errors.New("event agentId mismatch")

func (rt Router) handleAcks(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")

	err := _handleAcks(w, r, id, rt.sv)

	if err != nil {
		code := http.StatusBadRequest
		// Don't log connection drops
		if err != context.Canceled {
			log.Error().Err(err).Int("code", code).Msg("Fail ACK")
		}

		http.Error(w, err.Error(), code)
	}
}

// TODO: Handle UPGRADE and UNENROLL
func _handleAcks(w http.ResponseWriter, r *http.Request, id string, sv saved.CRUD) error {
	agent, err := authAgent(r, id, sv)
	if err != nil {
		return err
	}

	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	var req AckRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return err
	}

	log.Trace().RawJSON("raw", raw).Msg("Ack request")

	if err = _handleAckEvents(r.Context(), agent, req.Events, sv); err != nil {
		return err
	}

	// TODO: flesh this out
	resp := AckResponse{"acks"}

	data, err := json.Marshal(&resp)
	if err != nil {
		return err
	}

	if _, err = w.Write(data); err != nil {
		return err
	}

	return nil
}

func _handleAckEvents(ctx context.Context, agent *Agent, events []Event, sv saved.CRUD) error {

	// Retrieve each action
	m := map[string][]Action{}

	for _, ev := range events {

		if ev.AgentId != "" && ev.AgentId != agent.Id {
			return ErrEventAgentIdMismatch
		}

		action, ok := gCache.GetAction(ev.ActionId)
		if !ok {
			if err := sv.Read(ctx, AGENT_ACTION_SAVED_OBJECT_TYPE, ev.ActionId, &action); err != nil {
				return err
			}
		}

		// TODO: Handle not found diffently?  Ignore ACK?
		actionList := m[action.Type]
		m[action.Type] = append(actionList, action)
	}

	// TODO: handle UPGRADE and UNENROLL

	if actions, ok := m[TypePolicyChange]; ok {
		if err := _handlePolicyChange(ctx, agent, actions, sv); err != nil {
			return err
		}
	}

	return nil
}

func _handlePolicyChange(ctx context.Context, agent *Agent, actions []Action, sv saved.CRUD) error {

	// If more than one, pick the winner;
	// 0) Correctly typed
	// 1) Correct policy id
	// 2) Highest revision number

	var found bool
	var bestAction Action

	for _, a := range actions {
		switch {
		case a.Type != TypePolicyChange:
		case a.PolicyId != agent.PolicyId:
		case !found || a.PolicyRev > bestAction.PolicyRev:
			found = true
			bestAction = a
		}
	}

	if found {

		fields := map[string]interface{}{
			FieldPolicyRev: bestAction.PolicyRev,
			FieldPackages:  bestAction.AckData,
		}

		if err := sv.Update(ctx, AGENT_SAVED_OBJECT_TYPE, agent.Id, fields, saved.WithRefresh()); err != nil {
			return err
		}
	}

	return nil
}
