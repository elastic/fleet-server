// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/esclient"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/eval"
)

type fakeDoc struct {
	id        string
	seqNo     int64
	order     int
	source    json.RawMessage
	updatedAt time.Time
}

// fakeES implements the subset of the search API used by the Syncer.
type fakeES struct {
	mu      sync.Mutex
	docs    map[string]*fakeDoc
	seqNo   int64
	order   int
	uuid    string
	missing bool
	partial bool
	// uuidForbidden makes IndexUUID return the settings-read authorization error.
	uuidForbidden bool
	fail          error
	searches      []map[string]any
	pitsOpened    int
	pitsClosed    int
}

func newFakeES() *fakeES {
	return &fakeES{docs: map[string]*fakeDoc{}, uuid: "idx-1"}
}

func (f *fakeES) put(t *testing.T, id string, updatedAt time.Time, doc map[string]any) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	doc["updated_at"] = updatedAt.UTC().Format(time.RFC3339Nano)
	src, err := json.Marshal(doc)
	require.NoError(t, err)
	f.seqNo++
	existing, ok := f.docs[id]
	if !ok {
		f.order++
		existing = &fakeDoc{id: id, order: f.order}
		f.docs[id] = existing
	}
	existing.seqNo = f.seqNo
	existing.source = src
	existing.updatedAt = updatedAt
}

func (f *fakeES) putRaw(id string, src string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seqNo++
	f.order++
	f.docs[id] = &fakeDoc{id: id, order: f.order, seqNo: f.seqNo, source: json.RawMessage(src)}
}

func (f *fakeES) delete(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.docs, id)
}

func (f *fakeES) setFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = err
}

func (f *fakeES) setMissing(missing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.missing = missing
}

func (f *fakeES) setPartial(partial bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.partial = partial
}

func (f *fakeES) setUUID(uuid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uuid = uuid
}

// replaceSource changes a document without moving its _seq_no, as a recreated index can.
func (f *fakeES) replaceSource(t *testing.T, id string, doc map[string]any) {
	t.Helper()
	src, err := json.Marshal(doc)
	require.NoError(t, err)
	f.mu.Lock()
	defer f.mu.Unlock()
	existing, ok := f.docs[id]
	require.True(t, ok, id)
	existing.source = src
}

func (f *fakeES) pitBalance() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pitsOpened - f.pitsClosed
}

func (f *fakeES) recorded() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.searches)
}

func (f *fakeES) OpenPointInTime(context.Context, string, time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return "", f.fail
	}
	if f.missing {
		return "", &esclient.ResponseError{Status: 404, Type: "index_not_found_exception"}
	}
	f.pitsOpened++
	return "pit", nil
}

func (f *fakeES) ClosePointInTime(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pitsClosed++
	return nil
}

func (f *fakeES) IndexUUID(context.Context, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return "", f.fail
	}
	if f.uuidForbidden {
		return "", &esclient.ResponseError{Status: 403, Type: "security_exception", Reason: "unauthorized"}
	}
	if f.missing {
		return "", &esclient.ResponseError{Status: 404, Type: "index_not_found_exception"}
	}
	return f.uuid, nil
}

func (f *fakeES) Search(_ context.Context, index string, body []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	req["index"] = index
	f.searches = append(f.searches, req)
	if f.fail != nil {
		return nil, f.fail
	}
	if f.missing {
		return nil, &esclient.ResponseError{Status: 404, Type: "index_not_found_exception"}
	}

	all := make([]*fakeDoc, 0, len(f.docs))
	for _, d := range f.docs {
		all = append(all, d)
	}
	slices.SortFunc(all, func(a, b *fakeDoc) int { return a.order - b.order })

	matched := all
	if q, ok := req["query"].(map[string]any); ok {
		if rng, ok := q["range"].(map[string]any); ok {
			gte, err := time.Parse(time.RFC3339Nano, rng["updated_at"].(map[string]any)["gte"].(string))
			if err != nil {
				return nil, err
			}
			matched = nil
			for _, d := range all {
				if !d.updatedAt.Before(gte) {
					matched = append(matched, d)
				}
			}
		}
	}
	after := -1
	if sa, ok := req["search_after"].([]any); ok {
		after = int(sa[0].(float64))
	}
	size := int(req["size"].(float64))

	type hit struct {
		ID          string          `json:"_id"`
		SeqNo       int64           `json:"_seq_no"`
		PrimaryTerm int64           `json:"_primary_term"`
		Source      json.RawMessage `json:"_source"`
		Sort        []int           `json:"sort"`
	}
	hits := []hit{}
	for _, d := range matched {
		if d.order <= after {
			continue
		}
		if len(hits) == size {
			break
		}
		hits = append(hits, hit{ID: d.id, SeqNo: d.seqNo, PrimaryTerm: 1, Source: d.source, Sort: []int{d.order}})
	}
	resp := map[string]any{
		"hits": map[string]any{"total": map[string]any{"value": len(matched)}, "hits": hits},
	}
	if f.partial {
		resp["timed_out"] = true
		resp["_shards"] = map[string]any{"failed": 1}
	}
	if _, ok := req["aggs"]; ok {
		resp["aggregations"] = map[string]any{"index_doc_count": map[string]any{"doc_count": len(all)}}
	}
	return json.Marshal(resp)
}

func (f *fakeES) Bulk(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func flagDoc(key string, def bool) map[string]any {
	return map[string]any{
		"type": "flag",
		"flag": map[string]any{
			"key": key, "value_type": "boolean", "variations": []any{true, false}, "apps": []any{"kibana"},
			"environments": map[string]any{"production": map[string]any{"default": def}},
		},
	}
}

func credentialDoc(hash, clientID string) map[string]any {
	return map[string]any{
		"type":       "credential",
		"credential": map[string]any{"app": "kibana", "environment": "production", "sdk_key_hash": hash, "client_id": clientID},
	}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	return c.now
}

func newTestSyncer(es *fakeES, pageSize int) (*Syncer, *Store, *testClock) {
	st := New()
	s := NewSyncer(es, st, SyncOptions{
		Index:          ".feature-flags-definitions",
		PollInterval:   10 * time.Second,
		PollOverlap:    time.Minute,
		ResyncInterval: time.Hour,
		PageSize:       pageSize,
	}, zerolog.Nop())
	clock := &testClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	s.now = clock.Now
	return s, st, clock
}

func defaultOf(t *testing.T, snap *Snapshot, key string) any {
	t.Helper()
	f := snap.Flag(key)
	require.NotNil(t, f, key)
	return f.Def.Environments["production"].Default
}

func countFullReloads(searches []map[string]any) int {
	n := 0
	for _, s := range searches {
		if q, ok := s["query"].(map[string]any); ok {
			if _, ok := q["match_all"]; ok {
				n++
			}
		}
	}
	return n
}

func TestFullLoadPages(t *testing.T) {
	es := newFakeES()
	s, st, clock := newTestSyncer(es, 2)
	for i := range 5 {
		es.put(t, fmt.Sprintf("flag-%d", i), clock.Now(), flagDoc(fmt.Sprintf("f%d", i), true))
	}
	es.put(t, "cred", clock.Now(), credentialDoc("abc", "client-1"))
	es.putRaw("broken", `{"type": "flag", "flag": "not an object"}`)

	require.False(t, st.Ready())
	require.NoError(t, s.fullReload(t.Context()))
	require.True(t, st.Ready())

	snap := st.Load()
	assert.Equal(t, 7, snap.DocCount(), "unparsable documents still count")
	for i := range 5 {
		assert.NotNil(t, snap.Flag(fmt.Sprintf("f%d", i)))
	}
	assert.Len(t, snap.FlagsForApp("kibana"), 5)
	assert.NotNil(t, snap.CredentialBySDKKeyHash("abc"))
	assert.NotNil(t, snap.CredentialByClientID("client-1"))
	assert.Len(t, es.recorded(), 4, "7 documents in pages of 2")
	assert.Equal(t, "", es.recorded()[0]["index"], "a point-in-time search does not name the index")
	assert.Equal(t, []any{"_shard_doc"}, es.recorded()[0]["sort"])
	assert.NotNil(t, es.recorded()[0]["pit"])
	assert.Equal(t, 0, es.pitBalance())

	// The version depends only on the content.
	require.NoError(t, s.fullReload(t.Context()))
	assert.Equal(t, snap.Version, st.Load().Version)
}

func TestPollAppliesDelta(t *testing.T) {
	es := newFakeES()
	s, st, clock := newTestSyncer(es, 100)
	es.put(t, "a", clock.Now(), flagDoc("a", false))
	es.put(t, "b", clock.Now(), flagDoc("b", false))
	require.NoError(t, s.fullReload(t.Context()))
	before := st.Load()

	es.put(t, "a", clock.Advance(5*time.Second), flagDoc("a", true))
	clock.Advance(5 * time.Second)
	require.NoError(t, s.poll(t.Context()))

	after := st.Load()
	assert.Equal(t, true, defaultOf(t, after, "a"))
	assert.Equal(t, false, defaultOf(t, after, "b"))
	assert.NotEqual(t, before.Version, after.Version)
	assert.Same(t, before.Flag("b"), after.Flag("b"), "unchanged documents are not recompiled")
	assert.Equal(t, 1, countFullReloads(es.recorded()))
}

func TestPollSkipsRefetchedUnchangedDocs(t *testing.T) {
	es := newFakeES()
	s, st, clock := newTestSyncer(es, 100)
	es.put(t, "a", clock.Now(), flagDoc("a", false))
	require.NoError(t, s.fullReload(t.Context()))
	snap := st.Load()

	// "a" is inside the overlap window of both polls.
	clock.Advance(10 * time.Second)
	require.NoError(t, s.poll(t.Context()))
	clock.Advance(10 * time.Second)
	require.NoError(t, s.poll(t.Context()))

	searches := es.recorded()
	require.Len(t, searches, 3)
	last := searches[2]["query"].(map[string]any)["range"].(map[string]any)["updated_at"].(map[string]any)
	assert.Equal(t, clock.Now().Add(-10*time.Second-time.Minute).Format(time.RFC3339Nano), last["gte"])
	assert.Same(t, snap, st.Load(), "no new snapshot is published when nothing changed")
}

func TestPollDeleteAndCreateInSameIntervalReloads(t *testing.T) {
	es := newFakeES()
	s, st, clock := newTestSyncer(es, 100)
	start := clock.Now()
	es.put(t, "a", start.Add(-time.Hour), flagDoc("a", false))
	es.put(t, "b", start.Add(-time.Hour), flagDoc("b", false))
	require.NoError(t, s.fullReload(t.Context()))

	// Same index count before and after, but "a" is gone.
	es.delete("a")
	es.put(t, "c", clock.Advance(5*time.Second), flagDoc("c", true))
	clock.Advance(5 * time.Second)
	require.NoError(t, s.poll(t.Context()))

	snap := st.Load()
	assert.Nil(t, snap.Flag("a"))
	assert.NotNil(t, snap.Flag("b"))
	assert.NotNil(t, snap.Flag("c"))
	assert.Equal(t, 2, snap.DocCount())
	assert.Equal(t, 2, countFullReloads(es.recorded()), "the count mismatch triggered a full reload")
}

func TestFailedPollWidensWindow(t *testing.T) {
	es := newFakeES()
	s, st, clock := newTestSyncer(es, 100)
	loadedAt := clock.Now()
	require.NoError(t, s.fullReload(t.Context()))

	clock.Advance(10 * time.Second)
	es.setFail(errors.New("boom"))
	require.Error(t, s.poll(t.Context()))

	// A document updated during the failed interval, older than one poll overlap from now.
	es.put(t, "a", loadedAt.Add(time.Second), flagDoc("a", true))
	es.setFail(nil)
	clock.Advance(2 * time.Minute)
	require.NoError(t, s.poll(t.Context()))

	searches := es.recorded()
	gte := searches[len(searches)-1]["query"].(map[string]any)["range"].(map[string]any)["updated_at"].(map[string]any)["gte"]
	assert.Equal(t, loadedAt.Add(-time.Minute).Format(time.RFC3339Nano), gte, "the lower bound is kept after a failure")
	assert.NotNil(t, st.Load().Flag("a"))
}

func TestLoadContinuesWhenIndexUUIDIsForbidden(t *testing.T) {
	es := newFakeES()
	es.uuidForbidden = true
	s, st, clock := newTestSyncer(es, 100)
	es.put(t, "a", clock.Now(), flagDoc("a", false))

	require.NoError(t, s.fullReload(t.Context()))
	require.True(t, st.Ready())
	assert.Equal(t, "", st.Load().IndexUUID)
	assert.Equal(t, false, defaultOf(t, st.Load(), "a"))
	assert.Equal(t, 0, es.pitBalance())

	// Same _seq_no, different source. The source hash still forces a reparse on the next full reload.
	es.replaceSource(t, "a", flagDoc("a", true))
	require.NoError(t, s.fullReload(t.Context()))
	assert.Equal(t, true, defaultOf(t, st.Load(), "a"))

	clock.Advance(10 * time.Second)
	require.NoError(t, s.poll(t.Context()))
	assert.True(t, st.Ready())
}

func TestPartialSearchIsRejected(t *testing.T) {
	es := newFakeES()
	s, st, clock := newTestSyncer(es, 100)
	es.put(t, "a", clock.Now(), flagDoc("a", false))
	es.setPartial(true)

	require.ErrorIs(t, s.fullReload(t.Context()), errPartialSearch)
	require.False(t, st.Ready(), "a partial page is not published")
	assert.Equal(t, 0, es.pitBalance())
}

func TestIndexRecreationReloadsReusedVersions(t *testing.T) {
	es := newFakeES()
	s, st, clock := newTestSyncer(es, 100)
	es.put(t, "a", clock.Now(), flagDoc("a", false))
	require.NoError(t, s.fullReload(t.Context()))
	before := st.Load()

	// Same _seq_no and _primary_term, different source, because the index was recreated.
	es.setUUID("idx-2")
	es.replaceSource(t, "a", flagDoc("a", true))
	require.NoError(t, s.fullReload(t.Context()))

	after := st.Load()
	assert.Equal(t, "idx-2", after.IndexUUID)
	assert.NotEqual(t, before.Version, after.Version)
	assert.Equal(t, true, defaultOf(t, after, "a"))

	es.setUUID("idx-3")
	es.replaceSource(t, "a", flagDoc("a", false))
	clock.Advance(10 * time.Second)
	require.NoError(t, s.poll(t.Context()))
	assert.Equal(t, false, defaultOf(t, st.Load(), "a"), "a poll also reloads when the index uuid changes")
}

func TestMissingIndex(t *testing.T) {
	es := newFakeES()
	es.setMissing(true)
	s, st, clock := newTestSyncer(es, 100)

	require.NoError(t, s.fullReload(t.Context()))
	require.True(t, st.Ready())
	assert.Equal(t, 0, st.Load().DocCount())

	clock.Advance(10 * time.Second)
	require.NoError(t, s.poll(t.Context()), "polling a missing index is not an error")

	// Kibana creates the index with documents older than the poll window.
	es.setMissing(false)
	es.put(t, "a", clock.Now().Add(-time.Hour), flagDoc("a", true))
	clock.Advance(10 * time.Second)
	require.NoError(t, s.poll(t.Context()))
	assert.NotNil(t, st.Load().Flag("a"))

	// The index is deleted again.
	es.setMissing(true)
	clock.Advance(10 * time.Second)
	require.NoError(t, s.poll(t.Context()))
	assert.Equal(t, 0, st.Load().DocCount())
}

func TestPollLargeDeltaReloads(t *testing.T) {
	es := newFakeES()
	s, st, clock := newTestSyncer(es, 2)
	require.NoError(t, s.fullReload(t.Context()))
	for i := range 3 {
		es.put(t, fmt.Sprintf("f%d", i), clock.Now(), flagDoc(fmt.Sprintf("f%d", i), true))
	}
	clock.Advance(10 * time.Second)
	require.NoError(t, s.poll(t.Context()))
	assert.Equal(t, 3, st.Load().DocCount())
}

func TestParseDocPreservesLargeIntegers(t *testing.T) {
	snap := NewSnapshot(RawDoc{ID: "f", Source: json.RawMessage(
		`{"type":"flag","flag":{"key":"n","variations":[9007199254740993],"environments":{"production":{"default":9007199254740993}}}}`,
	)})
	f := snap.Flag("n")
	require.NotNil(t, f)
	res := eval.Evaluate(f, "production", eval.Context{}, func(string) *eval.Flag { return f })
	num, ok := res.Value.(json.Number)
	require.True(t, ok)
	assert.Equal(t, "9007199254740993", num.String())
}

func TestRunRetriesInitialLoadAndResyncs(t *testing.T) {
	es := newFakeES()
	es.setFail(errors.New("unavailable"))
	st := New()
	s := NewSyncer(es, st, SyncOptions{
		Index:          ".feature-flags-definitions",
		PollInterval:   10 * time.Millisecond,
		PollOverlap:    0,
		ResyncInterval: 30 * time.Millisecond,
	}, zerolog.Nop())

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	time.Sleep(30 * time.Millisecond)
	assert.False(t, st.Ready())
	es.setFail(nil)
	require.Eventually(t, st.Ready, 5*time.Second, 5*time.Millisecond)

	// An update with an old updated_at is outside every poll window; only the resync finds it.
	es.put(t, "a", time.Now().Add(-24*time.Hour), flagDoc("a", true))
	require.Eventually(t, func() bool { return st.Load().Flag("a") != nil }, 5*time.Second, 5*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Run did not return after cancellation")
	}
}
