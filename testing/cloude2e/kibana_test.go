// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build cloude2e

package cloude2e

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kibanaStatusBody is the subset of /api/status the Kibana client parses when
// it reads the version on construction.
const kibanaStatusBody = `{"name":"kibana","version":{"number":"9.5.0","build_snapshot":false}}`

// newKibanaStub returns a stub Kibana serving /api/status with the given
// status codes in order, repeating the last one once they run out, along with
// a counter of the requests it has served.
func newKibanaStub(t *testing.T, codes ...int) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/status", r.URL.Path)
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok, "expected basic auth credentials")
		assert.Equal(t, "elastic", user)
		assert.Equal(t, "changeme", pass)

		i := int(calls.Add(1)) - 1
		if i >= len(codes) {
			i = len(codes) - 1
		}
		if codes[i] == http.StatusOK {
			_, _ = w.Write([]byte(kibanaStatusBody))
			return
		}
		w.WriteHeader(codes[i])
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestNewKibanaClientRetriesUntilKibanaServes covers the failure mode where
// ECH reports the deployment as created while Kibana still answers 5xx.
func TestNewKibanaClientRetriesUntilKibanaServes(t *testing.T) {
	srv, calls := newKibanaStub(t, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusOK)

	client, err := newKibanaClient(srv.URL, "elastic", "changeme")
	require.NoError(t, err)
	require.Equal(t, int64(3), calls.Load())

	kibanaVersion := client.GetVersion()
	require.Equal(t, "9.5.0", kibanaVersion.String(), "expected the version to be read from /api/status")
}

func TestNewKibanaClientFailsFastOnAuthErrors(t *testing.T) {
	for name, code := range map[string]int{
		"unauthorized": http.StatusUnauthorized,
		"forbidden":    http.StatusForbidden,
	} {
		t.Run(name, func(t *testing.T) {
			srv, calls := newKibanaStub(t, code)

			_, err := newKibanaClient(srv.URL, "elastic", "changeme")
			require.Error(t, err)
			require.ErrorContains(t, err, "api/status")
			require.Equal(t, int64(1), calls.Load(), "a credentials failure must not be retried")
		})
	}
}

func TestKibanaRetryBackoffIsCapped(t *testing.T) {
	require.Equal(t, time.Second, kibanaRetryBackoff(1))
	require.Equal(t, 2*time.Second, kibanaRetryBackoff(2))
	require.Equal(t, 4*time.Second, kibanaRetryBackoff(3))
	require.Equal(t, 8*time.Second, kibanaRetryBackoff(4))
	require.Equal(t, kibanaRetryMaxWait, kibanaRetryBackoff(5))
	// Must stay capped and positive for every attempt kibanaMaxRetries allows.
	for attempt := 6; attempt <= kibanaMaxRetries+1; attempt++ {
		require.Equal(t, kibanaRetryMaxWait, kibanaRetryBackoff(attempt))
	}
}
