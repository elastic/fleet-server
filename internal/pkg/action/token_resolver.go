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
	"errors"
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/esutil"

	"github.com/elastic/go-elasticsearch/v8"
	lru "github.com/hashicorp/golang-lru"
	"github.com/rs/zerolog/log"
)

var ErrTokenNotFound = errors.New("token not found")

const cacheSize = 5000 // TODO: parameterize
const idField = "_id"

type TokenResolver struct {
	es    *elasticsearch.Client
	cache *lru.Cache

	tmpl *dsl.Tmpl
}

func NewTokenResolver(es *elasticsearch.Client) (*TokenResolver, error) {

	cache, err := lru.New(cacheSize)
	if err != nil {
		return nil, err
	}

	root := dsl.NewRoot()
	root.Param("seq_no_primary_term", true)
	root.Param("_source", []string{"_seq_no"})

	tmpl := dsl.NewTmpl()
	tokenIdField := tmpl.Bind(idField)

	root.Query().Bool().Filter().Term("_id", tokenIdField, nil)
	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}

	t := &TokenResolver{
		es:    es,
		cache: cache,
		tmpl:  tmpl,
	}
	return t, nil
}

func (r *TokenResolver) Resolve(ctx context.Context, token string) (seqno uint64, err error) {
	if token == "" {
		return seqno, ErrTokenNotFound
	}
	if v, ok := r.cache.Get(token); ok {
		seqno = v.(uint64)
		log.Debug().Str("token", token).Uint64("seqno", seqno).Msg("Found token cached")
		return
	}

	seqno, err = r.queryES(ctx, token)
	if err != nil {
		if err == ErrTokenNotFound {
			log.Debug().Str("token", token).Msg("Token not found")
		}
		return
	}
	r.cache.Add(token, seqno)

	return
}

func (r *TokenResolver) queryES(ctx context.Context, token string) (seqno uint64, err error) {
	query, err := r.tmpl.RenderOne(idField, token)
	if err != nil {
		return
	}

	res, err := r.es.Search(
		r.es.Search.WithIndex(IndexName),
		r.es.Search.WithBody(bytes.NewReader(query)),
		r.es.Search.WithContext(ctx),
	)

	if err != nil {
		return
	}
	defer res.Body.Close()
	err = esutil.CheckResponseError(res)
	if err != nil {
		return
	}

	var ares esutil.SearchResponse
	err = json.NewDecoder(res.Body).Decode(&ares)
	if err != nil {
		return
	}

	sz := len(ares.Result.Hits)
	if sz == 0 {
		return seqno, ErrTokenNotFound
	}
	return ares.Result.Hits[0].SeqNo, nil
}
