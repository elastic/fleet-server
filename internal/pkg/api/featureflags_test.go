// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/ofrep"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/store"
)

type staticSnapshot struct{ snap *store.Snapshot }

func (s staticSnapshot) Load() *store.Snapshot { return s.snap }

func testOFREPHandler(t *testing.T) http.Handler {
	t.Helper()
	sum := sha256.Sum256([]byte("sdk-key"))
	snap := store.NewSnapshot(
		store.RawDoc{ID: "c", Source: json.RawMessage(`{"type": "credential", "credential": {"app": "kibana", "environment": "production", "sdk_key_hash": "` + hex.EncodeToString(sum[:]) + `"}}`)},
		store.RawDoc{ID: "f", Source: json.RawMessage(`{"type": "flag", "flag": {"key": "my.flag", "variations": [true, false], "apps": ["kibana"], "environments": {"production": {"default": true}}}}`)},
	)
	return ofrep.NewHandler(staticSnapshot{snap}, ofrep.Options{})
}

func TestPathToOperationOFREP(t *testing.T) {
	for _, path := range []string{"/ofrep/v1/evaluate/flags", "/ofrep/v1/evaluate/flags/", "/ofrep/v1/evaluate/flags/some.flag"} {
		assert.Equal(t, "ofrep", pathToOperation(path), path)
	}
	assert.Empty(t, pathToOperation("/ofrep"))
}

func TestAddFeatureFlagsRouteHandler(t *testing.T) {
	existing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	limits := &config.ServerLimits{OFREPLimit: config.Limit{MaxBody: 1024}}
	h := addFeatureFlagsRouteHandler(existing, testOFREPHandler(t), nil, limits)

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sdk-key")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := post("/ofrep/v1/evaluate/flags/my.flag", `{"context": {}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"key": "my.flag", "value": true, "variant": "true", "reason": "STATIC"}`, rec.Body.String())
	assert.NotEmpty(t, rec.Header().Get("X-Request-Id"), "requests go through the logger middleware")

	rec = post("/ofrep/v1/evaluate/flags", `{"context": {}}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("ETag"))

	rec = post("/ofrep/v1/evaluate/flags/my.flag", `{"context": {"k": "`+strings.Repeat("x", 2048)+`"}}`)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "the OFREP body limit applies")

	rec = post("/api/status", ``)
	assert.Equal(t, http.StatusTeapot, rec.Code, "other routes are served by the existing handler")
}

func TestAddFeatureFlagsRouteHandlerRateLimit(t *testing.T) {
	limits := &config.ServerLimits{OFREPLimit: config.Limit{Interval: time.Hour, Burst: 1}}
	h := addFeatureFlagsRouteHandler(http.NotFoundHandler(), testOFREPHandler(t), []string{"http://localhost:5601"}, limits)

	codes := make([]int, 0, 2)
	for range 2 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ofrep/v1/evaluate/flags", strings.NewReader(`{"context": {}}`))
		req.Header.Set("Authorization", "Bearer sdk-key")
		req.Header.Set("Origin", "http://localhost:5601")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
		assert.Equal(t, "http://localhost:5601", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	assert.Equal(t, []int{http.StatusOK, http.StatusTooManyRequests}, codes)
}

func TestMaxConnectionsCoversOFREP(t *testing.T) {
	cfg := &config.Server{}
	cfg.Limits.MaxConnections = 1
	started := make(chan struct{})
	release := make(chan struct{})
	srv := NewServer("127.0.0.1:0", cfg, WithFeatureFlags(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	}), nil))

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		srv.handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ofrep/v1/evaluate/flags", nil))
	}()
	t.Cleanup(func() {
		close(release)
		<-requestDone
	})
	<-started

	rec := httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/status", nil))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestMaxConnectionsOFREPKeepsCORS(t *testing.T) {
	cfg := &config.Server{}
	cfg.Limits.MaxConnections = 1
	started := make(chan struct{})
	release := make(chan struct{})
	srv := NewServer("127.0.0.1:0", cfg, WithFeatureFlags(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	}), []string{"http://localhost:5601"}))

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		srv.handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ofrep/v1/evaluate/flags", nil))
	}()
	t.Cleanup(func() {
		close(release)
		<-requestDone
	})
	<-started

	preflight := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/ofrep/v1/evaluate/flags", nil)
	preflight.Header.Set("Origin", "http://localhost:5601")
	preflightRec := httptest.NewRecorder()
	srv.handler.ServeHTTP(preflightRec, preflight)
	assert.Equal(t, http.StatusNoContent, preflightRec.Code)
	assert.Equal(t, "http://localhost:5601", preflightRec.Header().Get("Access-Control-Allow-Origin"))

	blocked := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ofrep/v1/evaluate/flags", nil)
	blocked.Header.Set("Origin", "http://localhost:5601")
	blockedRec := httptest.NewRecorder()
	srv.handler.ServeHTTP(blockedRec, blocked)
	assert.Equal(t, http.StatusTooManyRequests, blockedRec.Code)
	assert.Equal(t, "http://localhost:5601", blockedRec.Header().Get("Access-Control-Allow-Origin"))
}

func TestMaxConnectionsPreservesOpAMPUpgrade(t *testing.T) {
	cfg := &config.Server{}
	cfg.Limits.MaxConnections = 1
	cfg.Features.EnableOpAMP = true
	oa := &OpAMPT{cfg: cfg}
	oa.handler = func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = conn.Close()
	}
	srv := NewServer("127.0.0.1:0", cfg, WithOpAMP(oa))
	ts := httptest.NewServer(srv.handler)
	t.Cleanup(ts.Close)

	conn, resp, err := websocket.DefaultDialer.Dial(strings.Replace(ts.URL, "http", "ws", 1)+"/v1/opamp", nil)
	require.NoError(t, err)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	conn.Close()
}
