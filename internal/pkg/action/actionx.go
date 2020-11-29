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
