// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package profile

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunProfiler(t *testing.T) {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Skip("Port 8080 must be free to run this test")
	}
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error)

	go func() {
		errCh <- RunProfiler(ctx, "localhost:8080")
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080/debug/pprof", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
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
