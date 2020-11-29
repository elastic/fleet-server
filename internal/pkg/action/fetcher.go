package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fleet/internal/pkg/esutil"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

type Fetcher struct {
	es    *elasticsearch.Client
	query *SearchQuery
}

func NewFetcher(es *elasticsearch.Client) (*Fetcher, error) {
	query, err := NewSearchQuery(
		WithExpiration(),
		WithSeqNo(),
		WithAgents(),
		WithSourceExclude("agents"),
	)

	if err != nil {
		return nil, err
	}

	f := &Fetcher{
		es:    es,
		query: query,
	}
	return f, nil
}

func (f *Fetcher) FetchAgentActions(ctx context.Context, agentId string, seqno int64) ([]ActionX, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	dslQuery, err := f.query.Render(map[string]interface{}{
		SeqNo:      seqno,
		Expiration: now,
		Agents:     []string{agentId},
	})

	if err != nil {
		return nil, err
	}

	es := f.es
	res, err := es.Search(
		es.Search.WithIndex(IndexName),
		es.Search.WithBody(bytes.NewReader(dslQuery)),
		es.Search.WithContext(ctx),
	)

	if err != nil {
		log.Warn().Err(err).Msg("Failed query new actions")
		return nil, err
	}
	defer res.Body.Close()
	err = esutil.CheckResponseError(res)

	if err != nil {
		log.Warn().Err(err).Msg("Error response for new actions")
		return nil, err
	}

	var ares esutil.SearchResponse

	err = json.NewDecoder(res.Body).Decode(&ares)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse new actions response")
		return nil, err
	}

	return HitsToActions(ares.Result.Hits), nil
}
