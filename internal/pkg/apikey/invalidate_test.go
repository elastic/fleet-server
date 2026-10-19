// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package apikey

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeInvalidateResponse(t *testing.T, invalidated, previouslyInvalidated []string, errorCount int) *http.Response {
	t.Helper()
	type invalidateResp struct {
		InvalidatedAPIKeys           []string `json:"invalidated_api_keys"`
		PreviouslyInvalidatedAPIKeys []string `json:"previously_invalidated_api_keys"`
		ErrorCount                   int      `json:"error_count"`
	}
	body, err := json.Marshal(invalidateResp{
		InvalidatedAPIKeys:           invalidated,
		PreviouslyInvalidatedAPIKeys: previouslyInvalidated,
		ErrorCount:                   errorCount,
	})
	require.NoError(t, err)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
			"Content-Type":      []string{"application/json"},
		},
	}
}

func logCtx(t *testing.T, buf *bytes.Buffer) context.Context {
	t.Helper()
	logger := zerolog.New(buf).Level(zerolog.WarnLevel)
	return logger.WithContext(context.Background())
}

func TestInvalidate_missingKey(t *testing.T) {
	mockES, mockTransport := esutil.MockESClient(t)
	var logBuf bytes.Buffer
	ctx := logCtx(t, &logBuf)

	mockTransport.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		return makeInvalidateResponse(t, nil, nil, 0), nil
	}

	err := Invalidate(ctx, mockES, "missing-id")

	require.NoError(t, err)
	assert.Contains(t, logBuf.String(), "missing-id", "expected warning log containing the missing key ID")
}

func TestInvalidate_previouslyInvalidatedKey(t *testing.T) {
	mockES, mockTransport := esutil.MockESClient(t)
	var logBuf bytes.Buffer
	ctx := logCtx(t, &logBuf)

	mockTransport.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		return makeInvalidateResponse(t, nil, []string{"prev-id"}, 0), nil
	}

	err := Invalidate(ctx, mockES, "prev-id")

	require.NoError(t, err)
	assert.Empty(t, logBuf.String(), "expected no warning for a previously-invalidated key")
}

func TestInvalidate_mixedResponse(t *testing.T) {
	mockES, mockTransport := esutil.MockESClient(t)
	var logBuf bytes.Buffer
	ctx := logCtx(t, &logBuf)

	mockTransport.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		return makeInvalidateResponse(t,
			[]string{"newly-id"},
			[]string{"prev-id"},
			0,
		), nil
	}

	err := Invalidate(ctx, mockES, "newly-id", "prev-id", "missing-id")

	require.NoError(t, err)
	assert.Contains(t, logBuf.String(), "missing-id", "expected warning for the not-found key")
	assert.NotContains(t, logBuf.String(), "newly-id", "no warning expected for newly-invalidated key")
	assert.NotContains(t, logBuf.String(), "prev-id", "no warning expected for previously-invalidated key")
}

func TestInvalidate_errorCount(t *testing.T) {
	mockES, mockTransport := esutil.MockESClient(t)
	ctx := context.Background()

	mockTransport.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		return makeInvalidateResponse(t, nil, nil, 2), nil
	}

	err := Invalidate(ctx, mockES, "some-id")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "2 error(s)")
}
