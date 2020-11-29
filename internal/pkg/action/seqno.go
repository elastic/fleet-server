package action

import (
	"context"
	"encoding/json"
	"errors"
	"fleet/internal/pkg/esutil"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

const IndexName = ".fleet-actions"

var ErrSeqNoNotFound = errors.New("sequence number not found") // This happens when the index is empty

func GetSeqNo(ctx context.Context, es *elasticsearch.Client) (seqno int64, err error) {
	seqno = -1

	const query = `
		{
		  "aggs": {
		    "max_action_seq_no": { "max": { "field": "_seq_no" } }
		  },
		  "size": 0
		}
	`
	res, err := es.Search(
		es.Search.WithIndex(IndexName),
		es.Search.WithSize(0),
		es.Search.WithBody(strings.NewReader(query)),
		es.Search.WithContext(ctx),
	)

	if err != nil {
		return
	}
	defer res.Body.Close()
	err = esutil.CheckResponseError(res)

	if err != nil {
		log.Warn().Err(err).Msg("Failed search for max(agents.action_seq_no)")
		return
	}

	var ares struct {
		Aggregations struct {
			MaxActionSeqID struct {
				Value *float64 `json:"value,omitempty"` // The value is null if there are no records
			} `json:"max_action_seq_no"`
		} `json:"aggregations"`
	}

	err = json.NewDecoder(res.Body).Decode(&ares)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse max(agents.action_seq_no) response")
	}

	if ares.Aggregations.MaxActionSeqID.Value != nil {
		seqno = int64(*ares.Aggregations.MaxActionSeqID.Value)
	} else {
		err = ErrSeqNoNotFound
	}
	return
}
