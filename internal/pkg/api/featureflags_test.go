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
	h := addFeatureFlagsRouteHandler(existing, testOFREPHandler(t), limits)

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
	h := addFeatureFlagsRouteHandler(http.NotFoundHandler(), testOFREPHandler(t), limits)

	codes := make([]int, 0, 2)
	for range 2 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ofrep/v1/evaluate/flags", strings.NewReader(`{"context": {}}`))
		req.Header.Set("Authorization", "Bearer sdk-key")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	assert.Equal(t, []int{http.StatusOK, http.StatusTooManyRequests}, codes)
}
