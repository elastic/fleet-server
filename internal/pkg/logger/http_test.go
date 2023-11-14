// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func TestMiddleware(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(context.Background())
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts, ok := CtxStartTime(r.Context())
		require.True(t, ok, "expected context to have start time")
		require.False(t, ts.Equal(time.Time{}), "expected start time to be non-zero")

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`hello, world`))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)

	Middleware(h).ServeHTTP(w, req)
	res := w.Result()
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	_, ok := res.Header[HeaderRequestID]
	require.True(t, ok, "expected to have a request ID")
	reqID := req.Header.Get(HeaderRequestID)
	require.NotEmpty(t, reqID)
}
