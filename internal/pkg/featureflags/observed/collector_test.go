// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package observed

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/esclient"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/eval"
)

type bulkOp struct {
	ID   string
	Body map[string]any
}

type fakeClient struct {
	mu      sync.Mutex
	missing bool
	// missingDocs are IDs answered with document_missing_exception.
	missingDocs map[string]bool
	bulks       [][]bulkOp
}

func (f *fakeClient) OpenPointInTime(context.Context, string, time.Duration) (string, error) {
	return "", nil
}

func (f *fakeClient) ClosePointInTime(context.Context, string) error { return nil }

func (f *fakeClient) IndexUUID(context.Context, string) (string, error) { return "idx-1", nil }

func (f *fakeClient) Search(context.Context, string, []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing {
		return nil, &esclient.ResponseError{Status: 404, Type: "index_not_found_exception"}
	}
	return []byte(`{"hits":{"hits":[]}}`), nil
}

func (f *fakeClient) Bulk(_ context.Context, body []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ops []bulkOp
	items := []map[string]any{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var meta map[string]map[string]any
		if err := json.Unmarshal(sc.Bytes(), &meta); err != nil {
			return nil, err
		}
		if !sc.Scan() {
			break
		}
		var src map[string]any
		if err := json.Unmarshal(sc.Bytes(), &src); err != nil {
			return nil, err
		}
		id := meta["update"]["_id"].(string)
		ops = append(ops, bulkOp{ID: id, Body: src})
		res := map[string]any{"_id": id, "status": 200}
		if f.missingDocs[id] {
			res = map[string]any{"_id": id, "status": 404, "error": map[string]any{"type": "document_missing_exception"}}
		}
		items = append(items, map[string]any{"update": res})
	}
	f.bulks = append(f.bulks, ops)
	return json.Marshal(map[string]any{"errors": false, "items": items})
}

func (f *fakeClient) lastBulk() []bulkOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bulks) == 0 {
		return nil
	}
	return f.bulks[len(f.bulks)-1]
}

func (f *fakeClient) bulkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bulks)
}

func newTestCollector(client esclient.Client, opts Options) (*Collector, *time.Time) {
	if opts.FlushInterval == 0 {
		opts.FlushInterval = time.Minute
	}
	if opts.MaxNewContextsPerFlush == 0 {
		opts.MaxNewContextsPerFlush = 1000
	}
	if opts.LastSeenResolution == 0 {
		opts.LastSeenResolution = time.Hour
	}
	opts.Index = ".feature-flags-observed-contexts"
	c := New(client, opts, zerolog.Nop())
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	return c, &now
}

func (c *Collector) observeSync(app, env string, ctx eval.Context) {
	c.add(observation{app: app, env: env, ctx: ctx, at: c.now()})
}

func TestCollectorWritesNewContext(t *testing.T) {
	client := &fakeClient{}
	c, _ := newTestCollector(client, Options{ExcludeAttributes: []string{"user.email"}})

	long := strings.Repeat("é", MaxValueLength+10)
	c.observeSync("kibana", "production", eval.Context{
		"targetingKey":     "org-1",
		"kibana.version":   "9.6.0",
		"organization.key": float64(123),
		"serverless":       true,
		"user.email":       "secret@example.com",
		"long":             long,
		"roles":            []any{"a", "b"},
	})
	c.flush(t.Context())

	ops := client.lastBulk()
	require.Len(t, ops, 1)
	assert.Equal(t, DocID("kibana", "production", "org-1"), ops[0].ID)

	upsert := ops[0].Body["upsert"].(map[string]any)
	assert.Equal(t, "kibana", upsert["app"])
	assert.Equal(t, "production", upsert["environment"])
	assert.Equal(t, "org-1", upsert["context_key"])
	assert.Equal(t, "2026-01-01T00:00:00Z", upsert["first_seen"])
	assert.Equal(t, "2026-01-01T00:00:00Z", upsert["last_seen"])
	assert.Equal(t, []any{"kibana.version", "long", "organization.key", "roles", "serverless", "targetingKey"}, upsert["attributes"])
	assert.Equal(t, map[string]any{
		"kibana.version":   "string",
		"long":             "string",
		"organization.key": "number",
		"roles":            "string",
		"serverless":       "boolean",
		"targetingKey":     "string",
	}, upsert["attribute_types"])

	ctx := upsert["context"].(map[string]any)
	assert.NotContains(t, ctx, "user.email")
	assert.Equal(t, []rune(long)[:MaxValueLength], []rune(ctx["long"].(string)))
	assert.Equal(t, `["a","b"]`, ctx["roles"])

	script := ops[0].Body["script"].(map[string]any)
	params := script["params"].(map[string]any)
	assert.Equal(t, upsert["context"], params["context"])
	assert.NotContains(t, params, "first_seen", "first_seen is only set on creation")
}

func TestCollectorIdentityUsesFullTargetingKey(t *testing.T) {
	client := &fakeClient{}
	c, _ := newTestCollector(client, Options{})

	prefix := strings.Repeat("a", MaxValueLength)
	c.observeSync("kibana", "production", eval.Context{"targetingKey": prefix + "1"})
	c.observeSync("kibana", "production", eval.Context{"targetingKey": prefix + "2"})
	c.flush(t.Context())

	ops := client.lastBulk()
	require.Len(t, ops, 2, "keys that share a truncated prefix are different contexts")
	assert.NotEqual(t, ops[0].ID, ops[1].ID)
	for _, op := range ops {
		upsert := op.Body["upsert"].(map[string]any)
		key := upsert["context_key"].(string)
		assert.Greater(t, len(key), MaxValueLength)
		stored := upsert["context"].(map[string]any)["targetingKey"].(string)
		assert.Equal(t, prefix, stored)
		assert.Equal(t, DocID("kibana", "production", key), op.ID)
	}
}

func TestCollectorContextKeyWithoutTargetingKey(t *testing.T) {
	client := &fakeClient{}
	c, _ := newTestCollector(client, Options{ExcludeAttributes: []string{"targetingKey"}})

	c.observeSync("kibana", "qa", eval.Context{"a": "1", "b": "2", "targetingKey": "excluded"})
	c.observeSync("kibana", "qa", eval.Context{"b": "2", "a": "1"})
	c.observeSync("kibana", "qa", eval.Context{"a": "1"})
	c.flush(t.Context())

	ops := client.lastBulk()
	require.Len(t, ops, 2, "identical contexts are deduplicated")
	for _, op := range ops {
		key := op.Body["upsert"].(map[string]any)["context_key"].(string)
		assert.Len(t, key, 64)
		assert.NotEqual(t, "excluded", key)
	}
}

func TestCollectorLastSeenResolution(t *testing.T) {
	client := &fakeClient{}
	c, now := newTestCollector(client, Options{LastSeenResolution: time.Hour})
	ctx := eval.Context{"targetingKey": "k"}

	c.observeSync("app", "env", ctx)
	c.flush(t.Context())
	require.Equal(t, 1, client.bulkCount())

	writtenAt := c.known[DocID("app", "env", "k")]
	*now = now.Add(30 * time.Minute)
	c.observeSync("app", "env", ctx)
	assert.Empty(t, c.pending, "a recently written context keeps no body")
	assert.Equal(t, writtenAt, c.known[DocID("app", "env", "k")], "the remembered time stays at the last write")
	assert.Equal(t, int64(0), c.retained.Load())
	c.flush(t.Context())
	assert.Equal(t, 1, client.bulkCount(), "last_seen moved less than the resolution")

	*now = now.Add(31 * time.Minute)
	c.observeSync("app", "env", eval.Context{"targetingKey": "k", "new": "attr"})
	c.flush(t.Context())
	require.Equal(t, 2, client.bulkCount())
	ops := client.lastBulk()
	require.Len(t, ops, 1)
	assert.NotContains(t, ops[0].Body, "upsert", "known contexts are only updated")
	params := ops[0].Body["script"].(map[string]any)["params"].(map[string]any)
	assert.Equal(t, "2026-01-01T01:01:00Z", params["last_seen"])
	assert.Equal(t, []any{"new", "targetingKey"}, params["attributes"])
}

func TestCollectorKnownContextLeavesRoomForNewOnes(t *testing.T) {
	client := &fakeClient{}
	c, now := newTestCollector(client, Options{MaxPending: 1, LastSeenResolution: time.Hour})

	c.observeSync("app", "env", eval.Context{"targetingKey": "known", "kibana.version": "9.6.0"})
	c.flush(t.Context())

	*now = now.Add(time.Minute)
	c.observeSync("app", "env", eval.Context{"targetingKey": "known", "kibana.version": "9.7.0"})
	c.observeSync("app", "env", eval.Context{"targetingKey": "new"})

	require.Len(t, c.pending, 1)
	assert.Equal(t, "new", c.pending[DocID("app", "env", "new")].ContextKey)
	assert.Equal(t, uint64(0), c.dropped.Load())
}

func TestCollectorCapsNewContextsPerAppAndEnvironment(t *testing.T) {
	client := &fakeClient{}
	c, _ := newTestCollector(client, Options{MaxNewContextsPerFlush: 2})
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		c.observeSync("app1", "prod", eval.Context{"targetingKey": k})
	}
	c.observeSync("app1", "qa", eval.Context{"targetingKey": "a"})
	c.observeSync("app2", "prod", eval.Context{"targetingKey": "a"})
	c.flush(t.Context())

	counts := map[string]int{}
	for _, op := range client.lastBulk() {
		u := op.Body["upsert"].(map[string]any)
		counts[u["app"].(string)+"/"+u["environment"].(string)]++
	}
	assert.Equal(t, map[string]int{"app1/prod": 2, "app1/qa": 1, "app2/prod": 1}, counts)
}

func TestCollectorSkipsMissingIndex(t *testing.T) {
	client := &fakeClient{missing: true}
	c, _ := newTestCollector(client, Options{})
	c.observeSync("app", "env", eval.Context{"targetingKey": "k"})
	c.flush(t.Context())
	assert.Equal(t, 0, client.bulkCount())
	assert.Empty(t, c.pending, "pending contexts are dropped")
}

func TestCollectorRewritesMissingDocuments(t *testing.T) {
	client := &fakeClient{}
	c, now := newTestCollector(client, Options{LastSeenResolution: time.Minute})
	ctx := eval.Context{"targetingKey": "k"}
	id := DocID("app", "env", "k")

	c.observeSync("app", "env", ctx)
	c.flush(t.Context())

	client.missingDocs = map[string]bool{id: true}
	*now = now.Add(2 * time.Minute)
	c.observeSync("app", "env", ctx)
	c.flush(t.Context())
	assert.NotContains(t, client.lastBulk()[0].Body, "upsert")

	client.missingDocs = nil
	*now = now.Add(2 * time.Minute)
	c.observeSync("app", "env", ctx)
	c.flush(t.Context())
	assert.Contains(t, client.lastBulk()[0].Body, "upsert", "a removed document is recreated")
}

func TestObserveNeverBlocks(t *testing.T) {
	c, _ := newTestCollector(&fakeClient{}, Options{BufferSize: 1})
	done := make(chan struct{})
	go func() {
		for range 10 {
			c.Observe("app", "env", eval.Context{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Observe blocked")
	}
	assert.Equal(t, uint64(9), c.dropped.Load())
}

func TestCollectorMaxPending(t *testing.T) {
	client := &fakeClient{}
	c, _ := newTestCollector(client, Options{MaxPending: 2})
	for _, k := range []string{"a", "b", "c"} {
		c.observeSync("app", "env", eval.Context{"targetingKey": k})
	}
	assert.Len(t, c.pending, 2)
	assert.Equal(t, uint64(1), c.dropped.Load())
}

func TestCollectorPendingByteBudget(t *testing.T) {
	c, _ := newTestCollector(&fakeClient{}, Options{MaxPendingBytes: 64})
	c.observeSync("app", "env", eval.Context{"targetingKey": "short"})
	c.observeSync("app", "env", eval.Context{"targetingKey": strings.Repeat("k", 10_000)})
	assert.Len(t, c.pending, 1)
	assert.Equal(t, uint64(1), c.dropped.Load())
	assert.Equal(t, "short", c.pending[DocID("app", "env", "short")].ContextKey)
}

func TestCollectorQueueByteBudget(t *testing.T) {
	c, _ := newTestCollector(&fakeClient{}, Options{MaxPendingBytes: 32, BufferSize: 8})
	c.Observe("app", "env", eval.Context{"targetingKey": strings.Repeat("k", 10_000)})
	assert.Equal(t, uint64(1), c.dropped.Load())
	assert.Empty(t, c.in)
}

func TestCollectorSplitsBulkBySize(t *testing.T) {
	client := &fakeClient{}
	c, _ := newTestCollector(client, Options{MaxBulkBytes: 1, MaxNewContextsPerFlush: 10})
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		c.observeSync("app", "env", eval.Context{"targetingKey": k, "pad": strings.Repeat("x", 40)})
	}
	c.flush(t.Context())
	assert.Equal(t, 5, client.bulkCount())
}

func TestCollectorRun(t *testing.T) {
	client := &fakeClient{}
	c := New(client, Options{
		Index:                  ".feature-flags-observed-contexts",
		FlushInterval:          10 * time.Millisecond,
		MaxNewContextsPerFlush: 10,
		LastSeenResolution:     time.Hour,
	}, zerolog.Nop())

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	c.Observe("app", "env", eval.Context{"targetingKey": "k"})
	require.Eventually(t, func() bool { return client.bulkCount() == 1 }, 5*time.Second, 5*time.Millisecond)

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}
