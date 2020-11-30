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

package action

import (
	"encoding/json"
	"fleet/internal/pkg/esutil"

	"github.com/rs/zerolog/log"
)

// New actions struct
// TODO: better name once the actions are consolidated
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

func HitsToActions(hits []esutil.Hit) []ActionX {
	var actions []ActionX

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
	return actions
}
