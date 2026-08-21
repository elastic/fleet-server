// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package profile

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunProfiler(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "localhost:8081")
	if err != nil {
		t.Skip("Port 8081 must be free to run this test")
	}
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error)

	go func() {
		errCh <- RunProfiler(ctx, "localhost:8081")
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:8081/debug/pprof", nil)
	require.NoError(t, err)

	var resp *http.Response
	for i := range 10 {
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		t.Logf("profile request %d failed with: %v, retrying...", i, err)
		time.Sleep(time.Millisecond * 200)
	}
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cancel()

	select {
	case err := <-errCh:
		require.NoError(t, err)
	default:
	}
}
