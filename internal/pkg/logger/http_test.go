// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts, ok := CtxStartTime(r.Context())
		require.True(t, ok, "expected context to have start time")
		require.False(t, ts.Equal(time.Time{}), "expected start time to be non-zero")

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`hello, world`))
	})

	var b bytes.Buffer
	logger := zerolog.New(&b).Level(zerolog.InfoLevel)
	ctx := logger.WithContext(context.Background())

	srv := httptest.NewUnstartedServer(Middleware(h))
	srv.Config.BaseContext = func(_ net.Listener) context.Context {
		return ctx
	}
	srv.Start()
	defer srv.Close()
	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", srv.URL, nil)
	require.NoError(t, err)

	res, err := srv.Client().Do(req)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	_, ok := res.Header[HeaderRequestID]
	require.True(t, ok, "expected to have a request ID")

	var obj map[string]any
	err = json.Unmarshal(b.Bytes(), &obj)
	require.NoError(t, err)
	v, ok := obj[ECSServerAddress]
	require.Truef(t, ok, "expected to find key: %s in %v", ECSServerAddress, obj)
	require.NotEmpty(t, v)
}
