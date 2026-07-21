// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/stretchr/testify/require"
)

func TestMetricsEndpoints(t *testing.T) {
	bi := build.Info{
		Version: "test",
	}
	cfg := &config.Config{
		HTTP: config.HTTP{
			Enabled: true,
			Host:    "localhost",
			Port:    8080,
		},
	}
	ctx := t.Context()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	srv, err := InitMetrics(ctx, cfg, bi, nil)
	require.NoError(t, err, "unable to start metrics server")
	defer srv.Stop() //nolint:errcheck // test server

	paths := []string{"/stats", "/metrics"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080"+path, nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			if path == "/stats" {
				var stats map[string]any
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&stats))

				httpServer, ok := stats["http_server"].(map[string]any)
				require.True(t, ok, "expected http_server object in /stats response, got: %v", stats)
				routes, ok := httpServer["routes"].(map[string]any)
				require.True(t, ok, "expected http_server.routes object, got: %v", httpServer)
				checkin, ok := routes["checkin"].(map[string]any)
				require.True(t, ok, "expected http_server.routes.checkin object, got: %v", routes)

				// limit_max_rate is the checkin capacity-rejection rate gauge used as
				// an autoscaling trigger; it must always be present (even if 0, since
				// no checkins have been rejected in this test) so that consumers like
				// fleet-controller's EPA config can rely on it being scraped.
				require.Contains(t, checkin, "limit_max_rate")
				require.InDelta(t, 0, checkin["limit_max_rate"], 0, "expected limit_max_rate to be 0 with no rejected checkins")
			}
		})
	}
}
