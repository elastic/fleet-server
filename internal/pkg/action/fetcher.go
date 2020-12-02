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
		ExpectExpiration(),
		ExpectSeqNo(),
		ExpectAgents(),
		Exclude("agents"),
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
