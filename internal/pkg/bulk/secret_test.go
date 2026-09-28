// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/go-elasticsearch/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newExtendedAPIWithStatus(t *testing.T, status int, body string) *ExtendedAPI {
	t.Helper()
	cli, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{"http://localhost:9200"},
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			h := make(http.Header)
			h.Set("X-Elastic-Product", "Elasticsearch")
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     h,
			}, nil
		}),
	})
	require.NoError(t, err)
	return &ExtendedAPI{Client: cli}
}

func TestExtendedAPIRead_NotFound_ReturnsSentinel(t *testing.T) {
	api := newExtendedAPIWithStatus(t, http.StatusNotFound, `{"error":{"reason":"No secret with id [abc]"}}`)
	_, err := api.Read(t.Context(), "abc")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "expected ErrSecretNotFound, got: %v", err)
}

func TestExtendedAPIRead_ServerError_ReturnsGenericError(t *testing.T) {
	api := newExtendedAPIWithStatus(t, http.StatusInternalServerError, `{"error":"internal"}`)
	_, err := api.Read(t.Context(), "abc")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSecretNotFound))
}

func TestExtendedAPIRead_Success(t *testing.T) {
	api := newExtendedAPIWithStatus(t, http.StatusOK, `{"value":"my-secret-value"}`)
	resp, err := api.Read(t.Context(), "abc")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "my-secret-value", resp.Value)
}
