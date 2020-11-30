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

package seqno

import (
	"bytes"
	"context"
	"encoding/json"
	"fleet/internal/pkg/action"
	"fleet/internal/pkg/esutil"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultCheckInterval = 1         // check every second for the new action
	defaultSeqNo         = int64(-1) // the _seq_no in elasticsearch start with 0
)

type Monitor struct {
	es            *elasticsearch.Client
	query         *action.SearchQuery
	index         string
	checkInterval time.Duration
	seqno         int64

	log zerolog.Logger

	outCh chan []esutil.Hit
}

type MonitorOption func(*Monitor)

func NewMonitor(es *elasticsearch.Client, index string, opts ...MonitorOption) *Monitor {
	m := &Monitor{
		es:            es,
		index:         index,
		checkInterval: defaultCheckInterval * time.Second,
		seqno:         defaultSeqNo,
		log:           log.With().Str("index", index).Str("ctx", "seqno monitor").Logger(),
		outCh:         make(chan []esutil.Hit, 1),
	}

	for _, opt := range opts {
		opt(m)
	}

	var err error
	m.query, err = action.NewSearchQuery(
		action.WithExpiration(),
		action.WithSeqNo(),
	)

	if err != nil {
		panic(err)
	}

	return m
}

func WithCheckInterval(interval time.Duration) MonitorOption {
	return func(m *Monitor) {
		m.checkInterval = interval
	}
}

func WithSeqNo(seqno int64) MonitorOption {
	return func(m *Monitor) {
		m.seqno = seqno
	}
}

func (m *Monitor) Output() <-chan []esutil.Hit {
	return m.outCh
}

func (m *Monitor) Run(ctx context.Context) (err error) {
	m.log.Info().Int64("seqno", m.seqno).Msg("Start")
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("Failed, exited")
			return
		}
		log.Info().Msg("Exited")
	}()

	// Initial check for new documents
	m.checkNewDocuments(ctx)

	t := time.NewTimer(m.checkInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// Check for new actions
			m.checkNewDocuments(ctx)
			t.Reset(m.checkInterval)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *Monitor) checkNewDocuments(ctx context.Context) {
	now := time.Now().UTC().Format(time.RFC3339)

	dslQuery, err := m.query.Render(map[string]interface{}{
		action.SeqNo:      m.seqno,
		action.Expiration: now,
	})
	if err != nil {
		return
	}

	es := m.es
	res, err := es.Search(
		es.Search.WithIndex(m.index),
		es.Search.WithBody(bytes.NewReader(dslQuery)),
		es.Search.WithContext(ctx),
	)

	if err != nil {
		log.Warn().Err(err).Msg("Failed query for new documents")
		return
	}
	defer res.Body.Close()
	err = esutil.CheckResponseError(res)

	if err != nil {
		log.Warn().Err(err).Msg("Error response for new documents")
		return
	}

	var ares esutil.SearchResponse

	err = json.NewDecoder(res.Body).Decode(&ares)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse query response")
		return
	}

	sz := len(ares.Result.Hits)
	if sz > 0 {
		maxSeqNo := ares.Result.Hits[sz-1].SeqNo
		if int64(maxSeqNo) > m.seqno {
			m.seqno = int64(maxSeqNo)
		}

		select {
		case m.outCh <- ares.Result.Hits:
		case <-ctx.Done():
		}
	}
	return
}
