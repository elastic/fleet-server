// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/esclient"
)

const (
	defaultPageSize = 1000
	pitKeepAlive    = time.Minute
)

// errPartialSearch is returned when Elasticsearch reports a timed-out or incomplete search.
var errPartialSearch = errors.New("elasticsearch search was partial")

// SyncOptions configures the Syncer.
type SyncOptions struct {
	Index          string
	PollInterval   time.Duration
	PollOverlap    time.Duration
	ResyncInterval time.Duration
	// PageSize is the number of documents fetched per request. Defaults to 1000.
	PageSize int
}

// Syncer keeps a Store in sync with the definitions index.
//
//   - On start it does a full load, paging a point in time with search_after on _shard_doc.
//     The store is not ready until it succeeds.
//   - Every poll interval it sends one search for documents with updated_at >= the start of the last
//     successful poll minus the overlap. A global aggregation in the same request returns the
//     index-wide document count. Documents fetched again with the same _seq_no and _primary_term
//     are skipped, but only while the index UUID is unchanged. A recreated index is fully reloaded.
//     After applying the changes, a store count that differs from the index count means documents
//     were deleted, and a full reload follows.
//   - A timed-out search or a search with failed shards is an error, so a partial page is never published.
//   - Every resync interval it does an unconditional full reload.
//   - A missing index is an empty, ready store.
//
// Errors are logged and retried; Run only returns when its context is done.
type Syncer struct {
	client esclient.Client
	store  *Store
	opts   SyncOptions
	log    zerolog.Logger
	now    func() time.Time

	// lowerBound is the start time of the last successful poll or full reload.
	lowerBound   time.Time
	indexMissing bool
}

// NewSyncer returns a Syncer that publishes into store.
func NewSyncer(client esclient.Client, store *Store, opts SyncOptions, log zerolog.Logger) *Syncer {
	if opts.PageSize <= 0 {
		opts.PageSize = defaultPageSize
	}
	return &Syncer{
		client: client,
		store:  store,
		opts:   opts,
		log:    log,
		now:    time.Now,
	}
}

// Run loads the definitions and keeps them in sync until ctx is done.
func (s *Syncer) Run(ctx context.Context) error {
	for !s.store.Ready() {
		if err := s.fullReload(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.log.Warn().Err(err).Msg("initial load of feature flags definitions failed, retrying")
			if !sleep(ctx, s.opts.PollInterval) {
				return ctx.Err()
			}
		}
	}
	s.log.Info().Int("documents", s.store.Load().DocCount()).Msg("feature flags definitions loaded")

	poll := time.NewTicker(s.opts.PollInterval)
	defer poll.Stop()
	resync := time.NewTicker(s.opts.ResyncInterval)
	defer resync.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-resync.C:
			if err := s.fullReload(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn().Err(err).Msg("feature flags definitions resync failed")
			}
		case <-poll.C:
			if err := s.poll(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn().Err(err).Msg("feature flags definitions poll failed")
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

type searchHit struct {
	ID          string            `json:"_id"`
	SeqNo       int64             `json:"_seq_no"`
	PrimaryTerm int64             `json:"_primary_term"`
	Source      json.RawMessage   `json:"_source"`
	Sort        []json.RawMessage `json:"sort"`
}

type searchResponse struct {
	TimedOut bool   `json:"timed_out"`
	PITID    string `json:"pit_id"`
	Shards   struct {
		Failed int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []searchHit `json:"hits"`
	} `json:"hits"`
	Aggregations struct {
		IndexDocCount struct {
			DocCount int `json:"doc_count"`
		} `json:"index_doc_count"`
	} `json:"aggregations"`
}

var matchAll = map[string]any{"match_all": map[string]any{}}

type pitQuery struct {
	ID        string `json:"id"`
	KeepAlive string `json:"keep_alive,omitempty"`
}

type searchRequest struct {
	Size             int               `json:"size"`
	SeqNoPrimaryTerm bool              `json:"seq_no_primary_term"`
	TrackTotalHits   bool              `json:"track_total_hits"`
	Sort             []string          `json:"sort"`
	Query            any               `json:"query"`
	SearchAfter      []json.RawMessage `json:"search_after,omitempty"`
	Aggs             map[string]any    `json:"aggs,omitempty"`
	PIT              *pitQuery         `json:"pit,omitempty"`
}

// newSearchRequest returns a request for one page of documents, with their _seq_no and _primary_term.
// The delta poll is a single page sorted by _doc. A full reload uses a point in time and _shard_doc instead:
// _doc order is shard-local, so search_after on it can skip documents.
func (s *Syncer) newSearchRequest(trackTotalHits bool, query any) *searchRequest {
	return &searchRequest{
		Size:             s.opts.PageSize,
		SeqNoPrimaryTerm: true,
		TrackTotalHits:   trackTotalHits,
		Sort:             []string{"_doc"},
		Query:            query,
	}
}

func (s *Syncer) newPITRequest(pitID string) *searchRequest {
	req := s.newSearchRequest(false, matchAll)
	req.Sort = []string{"_shard_doc"}
	req.PIT = &pitQuery{ID: pitID, KeepAlive: "1m"}
	return req
}

func (s *Syncer) search(ctx context.Context, index string, body *searchRequest) (*searchResponse, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	data, err := s.client.Search(ctx, index, raw)
	if err != nil {
		return nil, err
	}
	var resp searchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}
	if resp.TimedOut || resp.Shards.Failed > 0 {
		return nil, errPartialSearch
	}
	return &resp, nil
}

func (s *Syncer) markIndexMissing(missing bool) {
	if missing && !s.indexMissing {
		s.log.Debug().Str("index", s.opts.Index).Msg("feature flags definitions index does not exist yet, serving no flags")
	}
	s.indexMissing = missing
}

// entryFor reuses the parsed entry of the current snapshot when the document did not change.
// The index UUID has to match: a recreated index can reuse _seq_no and _primary_term.
func entryFor(prev *Snapshot, indexUUID string, raw RawDoc) docEntry {
	if prev != nil && prev.IndexUUID == indexUUID {
		if e, ok := prev.docs[raw.ID]; ok && e.version == raw.Version {
			return e
		}
	}
	return parseDoc(raw)
}

func rawDoc(hit searchHit) RawDoc {
	return RawDoc{ID: hit.ID, Version: DocVersion{SeqNo: hit.SeqNo, PrimaryTerm: hit.PrimaryTerm}, Source: hit.Source}
}

// fullReload replaces the snapshot with the whole content of the index.
// Pages are read from one point in time, ordered by _shard_doc, which is unique for the life of that point in time.
func (s *Syncer) fullReload(ctx context.Context) error {
	start := s.now()
	uuid, err := s.client.IndexUUID(ctx, s.opts.Index)
	if errors.Is(err, esclient.ErrIndexNotFound) {
		s.publishEmpty(start)
		return nil
	}
	if err != nil {
		return err
	}
	pitID, err := s.client.OpenPointInTime(ctx, s.opts.Index, pitKeepAlive)
	if errors.Is(err, esclient.ErrIndexNotFound) {
		s.publishEmpty(start)
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.client.ClosePointInTime(cctx, pitID); err != nil {
			s.log.Debug().Err(err).Msg("failed to close feature flags point in time")
		}
	}()

	prev := s.store.Load()
	if prev != nil && prev.IndexUUID != uuid {
		prev = nil
	}
	docs := map[string]docEntry{}
	var searchAfter []json.RawMessage
	for {
		body := s.newPITRequest(pitID)
		body.SearchAfter = searchAfter
		resp, err := s.search(ctx, "", body)
		if errors.Is(err, esclient.ErrIndexNotFound) {
			s.publishEmpty(start)
			return nil
		}
		if err != nil {
			return err
		}
		if resp.PITID != "" {
			pitID = resp.PITID
		}
		hits := resp.Hits.Hits
		for _, hit := range hits {
			raw := rawDoc(hit)
			docs[raw.ID] = entryFor(prev, uuid, raw)
		}
		if len(hits) < s.opts.PageSize {
			break
		}
		searchAfter = hits[len(hits)-1].Sort
		if len(searchAfter) == 0 {
			return errors.New("search response is missing sort values")
		}
	}
	s.markIndexMissing(false)
	s.store.publish(buildSnapshot(docs, uuid))
	s.lowerBound = start
	return nil
}

func (s *Syncer) publishEmpty(start time.Time) {
	s.markIndexMissing(true)
	s.store.publish(buildSnapshot(map[string]docEntry{}, ""))
	s.lowerBound = start
}

// poll applies the documents updated since the last successful poll.
func (s *Syncer) poll(ctx context.Context) error {
	start := s.now()
	snap := s.store.Load()
	if snap == nil {
		return s.fullReload(ctx)
	}
	uuid, err := s.client.IndexUUID(ctx, s.opts.Index)
	if errors.Is(err, esclient.ErrIndexNotFound) {
		s.markIndexMissing(true)
		if snap.DocCount() > 0 {
			s.store.publish(buildSnapshot(map[string]docEntry{}, ""))
		}
		s.lowerBound = start
		return nil
	}
	if err != nil {
		return err
	}
	if snap.IndexUUID != uuid {
		return s.fullReload(ctx)
	}

	from := s.lowerBound.Add(-s.opts.PollOverlap)
	body := s.newSearchRequest(true, map[string]any{
		"range": map[string]any{
			"updated_at": map[string]any{
				"gte":    from.UTC().Format(time.RFC3339Nano),
				"format": "strict_date_optional_time",
			},
		},
	})
	// A global aggregation ignores the query, so it counts every document of the index.
	body.Aggs = map[string]any{"index_doc_count": map[string]any{"global": map[string]any{}}}
	resp, err := s.search(ctx, s.opts.Index, body)
	if errors.Is(err, esclient.ErrIndexNotFound) {
		s.markIndexMissing(true)
		if snap.DocCount() > 0 {
			s.store.publish(buildSnapshot(map[string]docEntry{}, ""))
		}
		s.lowerBound = start
		return nil
	}
	if err != nil {
		// Keep the lower bound: the next poll's window widens until one succeeds.
		return err
	}
	if s.indexMissing {
		// The index has just been created: load it all.
		return s.fullReload(ctx)
	}
	if resp.Hits.Total.Value > len(resp.Hits.Hits) {
		// More changes than fit in a page: a full reload is simpler than paging the delta.
		return s.fullReload(ctx)
	}

	var docs map[string]docEntry
	for _, hit := range resp.Hits.Hits {
		raw := rawDoc(hit)
		if v, ok := snap.docVersion(raw.ID); ok && v == raw.Version {
			continue
		}
		if docs == nil {
			docs = maps.Clone(snap.docs)
		}
		docs[raw.ID] = parseDoc(raw)
	}
	next := snap
	if docs != nil {
		next = buildSnapshot(docs, snap.IndexUUID)
		s.store.publish(next)
		s.log.Debug().Int("documents", next.DocCount()).Msg("feature flags definitions updated")
	}

	if indexCount := resp.Aggregations.IndexDocCount.DocCount; next.DocCount() != indexCount {
		s.log.Debug().Int("store_count", next.DocCount()).Int("index_count", indexCount).
			Msg("feature flags definitions count mismatch, reloading")
		return s.fullReload(ctx)
	}
	s.lowerBound = start
	return nil
}
