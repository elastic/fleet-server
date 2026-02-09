// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestPathToOperation(t *testing.T) {
	tests := []struct {
		path string
		op   string
	}{
		{"/api/status/", "status"},
		{"/api/status", "status"},
		{"/api/status/toolong", ""},
		{"/api/fleet/uploads", "uploadBegin"},
		{"/api/fleet/upload", ""},
		{"/api/fleet/agents/some-id", "enroll"},
		{"/api/fleet/agents/some-id/acks", "acks"},
		{"/api/fleet/agents/some-id/checkin", "checkin"},
		{"/api/fleet/uploads/some-id", "uploadComplete"},
		{"/api/fleet/uploads/some-id/0", "uploadChunk"},
		{"/api/fleet/file", ""},
		{"/api/fleet/file/abc", "deliverFile"},
		{"/api/fleet/artifacts/some-id/hash", "artifact"},
		{"/api/fleet/agents/some-id/audit/unenroll", "audit-unenroll"},
		{"/v1/opamp", "opamp"},
		{"/v1/opamp/", "opamp"},
		{"/api/fleet/agents/some-id/other/unenroll", ""},
		{"/api/fleet/unimplemented/some-id", ""},
		{"/api/flet/agents/some-id/acks", ""},
		{"/api/fleet/agents/some-id/other", ""},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("testcase %d", i), func(t *testing.T) {
			assert.Equal(t, tt.op, pathToOperation(tt.path))
		})
	}
}

func testStatusServer(t *testing.T, cfg *config.ServerLimits) http.Handler {
	t.Helper()
	l := Limiter(cfg)

	r := chi.NewRouter()
	r.Use(l.middleware)
	r.Get("/api/status", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	})
	return r
}

func TestLimiter(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *config.ServerLimits
		status int
	}{{
		name: "enabled",
		cfg: &config.ServerLimits{
			StatusLimit: config.Limit{
				Interval: time.Second,
				Burst:    1,
				Max:      1,
			},
		},
		status: http.StatusOK,
	}, {
		name: "limit reached (negative values)",
		cfg: &config.ServerLimits{
			StatusLimit: config.Limit{
				Interval: -1 * time.Second,
				Burst:    -1,
				Max:      -1,
			},
		},
		status: http.StatusTooManyRequests,
	}, {
		name:   "disabled (zero values)",
		cfg:    &config.ServerLimits{},
		status: http.StatusOK,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := testStatusServer(t, tt.cfg)
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/api/status", nil)

			h.ServeHTTP(w, r)
			resp := w.Result()
			resp.Body.Close()
			assert.Equal(t, tt.status, resp.StatusCode)
		})
	}
}
