// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := InitMetrics(ctx, cfg, bi, nil)
	require.NoError(t, err, "unable to start metrics server")
	defer srv.Stop()

	paths := []string{"/stats", "/metrics"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080"+path, nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}
