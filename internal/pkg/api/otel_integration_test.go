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
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/stretchr/testify/require"
)

func TestMetricsEndpoints(t *testing.T) {
	bi := build.Info{
		Version: "test",
	}
	cfg := config.HTTP{
		Enabled: true,
		Host:    "localhost",
		Port:    8080,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	wrapper, err := InitOTEL(bi, nil, cfg)
	require.NoError(t, err, "unable to start metrics server")
	go func() {
		if err := wrapper.Start(); err != nil {
			t.Logf("http stats server error: %v", err)
		}
	}()
	defer wrapper.Shutdown(ctx) //nolint:errcheck // test server

	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080/stats", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
