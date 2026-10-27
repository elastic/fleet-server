// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package featureflags

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
)

type fakeClient struct {
	mu    sync.Mutex
	docs  []map[string]any
	bulks int
}

func (f *fakeClient) Search(_ context.Context, index string, _ []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	hits := []map[string]any{}
	// A full reload searches a point in time and does not name the index.
	if index == ".feature-flags-definitions" || index == "" {
		for i, d := range f.docs {
			hits = append(hits, map[string]any{"_id": d["id"], "_seq_no": i, "_primary_term": 1, "_source": d["source"], "sort": []int{i}})
		}
	}
	return json.Marshal(map[string]any{
		"hits":         map[string]any{"total": map[string]any{"value": len(hits)}, "hits": hits},
		"aggregations": map[string]any{"index_doc_count": map[string]any{"doc_count": len(hits)}},
	})
}

func (f *fakeClient) OpenPointInTime(context.Context, string, time.Duration) (string, error) {
	return "pit", nil
}

func (f *fakeClient) ClosePointInTime(context.Context, string) error { return nil }

func (f *fakeClient) IndexUUID(context.Context, string) (string, error) { return "idx-1", nil }

func (f *fakeClient) Bulk(context.Context, []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bulks++
	return []byte(`{"errors":false,"items":[]}`), nil
}

func (f *fakeClient) bulkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bulks
}

func TestModule(t *testing.T) {
	sum := sha256.Sum256([]byte("key"))
	client := &fakeClient{docs: []map[string]any{
		{"id": "c", "source": map[string]any{"type": "credential", "credential": map[string]any{
			"app": "kibana", "environment": "production", "sdk_key_hash": hex.EncodeToString(sum[:]),
		}}},
		{"id": "f", "source": map[string]any{"type": "flag", "flag": map[string]any{
			"key": "my.flag", "variations": []any{true, false}, "apps": []any{"kibana"},
			"environments": map[string]any{"production": map[string]any{"default": true}},
		}}},
	}}

	var cfg config.FeatureFlagsService
	cfg.InitDefaults()
	cfg.Enabled = true
	cfg.ObservedContexts.Enabled = true
	cfg.ObservedContexts.FlushInterval = 10 * time.Millisecond

	m := New(cfg, client, zerolog.Nop())
	assert.False(t, m.Ready())

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	require.Eventually(t, m.Ready, 5*time.Second, 5*time.Millisecond)

	req := httptest.NewRequest(http.MethodPost, "/ofrep/v1/evaluate/flags/my.flag", strings.NewReader(`{"context":{"targetingKey":"u"}}`))
	req.Header.Set("Authorization", "Bearer key")
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"key":"my.flag","value":true,"variant":"true","reason":"STATIC"}`, rec.Body.String())

	require.Eventually(t, func() bool { return client.bulkCount() > 0 }, 5*time.Second, 5*time.Millisecond, "the observed context is flushed")

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}
