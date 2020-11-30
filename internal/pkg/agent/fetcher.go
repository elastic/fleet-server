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

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/esutil"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

const (
	fieldID   = "_id"
	IndexName = ".fleet-agents"
)

var (
	ErrNotFound = errors.New("agent not found")
)

type Fetcher struct {
	es   *elasticsearch.Client
	tmpl *dsl.Tmpl
}

func NewFetcher(es *elasticsearch.Client) (*Fetcher, error) {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()

	tokenFieldID := tmpl.Bind(fieldID)

	root.Query().Bool().Filter().Term(fieldID, tokenFieldID, nil)
	root.Source().Includes("action_seq_no")

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}

	f := &Fetcher{
		es:   es,
		tmpl: tmpl,
	}
	return f, nil
}

func (f *Fetcher) FetchAgentSeqNo(ctx context.Context, agentId string) (seqno uint64, err error) {
	dslQuery, err := f.tmpl.RenderOne(fieldID, agentId)

	if err != nil {
		return
	}

	es := f.es
	res, err := es.Search(
		es.Search.WithIndex(IndexName),
		es.Search.WithBody(bytes.NewReader(dslQuery)),
		es.Search.WithContext(ctx),
	)

	if err != nil {
		log.Warn().Err(err).Msg("Failed query agent")
		return
	}
	defer res.Body.Close()
	err = esutil.CheckResponseError(res)

	if err != nil {
		log.Warn().Err(err).Msg("Error response for agent")
		return
	}

	var ares esutil.SearchResponse

	err = json.NewDecoder(res.Body).Decode(&ares)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse agent hits")
		return
	}

	if len(ares.Result.Hits) == 0 {
		return seqno, ErrNotFound
	}

	var minAgent struct {
		ActionSeqNo *uint64 `json:"action_seq_no"`
	}

	err = json.Unmarshal(ares.Result.Hits[0].Source, &minAgent)
	if err != nil {
		return
	}
	if minAgent.ActionSeqNo == nil {
		return seqno, ErrNotFound
	}

	return *minAgent.ActionSeqNo, nil
}
