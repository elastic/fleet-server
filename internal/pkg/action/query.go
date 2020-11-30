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

import "fleet/internal/pkg/dsl"

const (
	SeqNo      = "_seq_no"
	Expiration = "expiration"
	Agents     = "agents"
)

type SearchQuery struct {
	tmpl *dsl.Tmpl

	tokenSeqNo, tokenExpiration, tokenAgents dsl.Token

	sourceExclude []string
}

type SearchOptFunc func(*SearchQuery)

func WithSeqNo() SearchOptFunc {
	return func(q *SearchQuery) {
		q.tokenSeqNo = q.tmpl.Bind(SeqNo)
	}
}

func WithExpiration() SearchOptFunc {
	return func(q *SearchQuery) {
		q.tokenExpiration = q.tmpl.Bind(Expiration)
	}
}

func WithAgents() SearchOptFunc {
	return func(q *SearchQuery) {
		q.tokenAgents = q.tmpl.Bind(Agents)
	}
}

func WithSourceExclude(sourceExclude ...string) SearchOptFunc {
	return func(q *SearchQuery) {
		q.sourceExclude = sourceExclude
	}
}

func NewSearchQuery(opts ...SearchOptFunc) (*SearchQuery, error) {
	q := &SearchQuery{
		tmpl: dsl.NewTmpl(),
	}

	for _, opt := range opts {
		opt(q)
	}

	root := dsl.NewRoot()
	root.Param("seq_no_primary_term", true)
	if len(q.sourceExclude) > 0 {
		root.Source().Excludes(q.sourceExclude...)
	}

	if q.tokenSeqNo != "" || q.tokenExpiration != "" || q.tokenAgents != "" {
		filterNode := root.Query().Bool().Filter()
		if q.tokenSeqNo != "" {
			filterNode.Range(SeqNo, dsl.WithRangeGT(q.tokenSeqNo))
		}
		if q.tokenExpiration != "" {
			filterNode.Range(Expiration, dsl.WithRangeGT(q.tokenExpiration))
		}
		if q.tokenAgents != "" {
			filterNode.Terms(Agents, q.tokenAgents, nil)
		}
	}

	root.Sort().SortOrder(SeqNo, dsl.SortAscend)

	if err := q.tmpl.Resolve(root); err != nil {
		return nil, err
	}

	return q, nil
}

func (q *SearchQuery) Render(m map[string]interface{}) ([]byte, error) {
	return q.tmpl.Render(m)
}
