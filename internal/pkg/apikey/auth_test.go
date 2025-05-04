// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/stretchr/testify/assert"
)

const (
	rawToken = " foo:bar"
)

func setup(t *testing.T, statusCode int) (context.Context, *APIKey, *elasticsearch.Client) {
	token := base64.StdEncoding.EncodeToString([]byte(rawToken))
	apiKey, err := NewAPIKeyFromToken(token)
	assert.NoError(t, err)
	ctx := t.Context()

	mockES, mockTransport := esutil.MockESClient(t)
	mockTransport.RoundTripFn = func(req *http.Request) (*http.Response, error) { return &http.Response{StatusCode: statusCode}, nil }

	return ctx, apiKey, mockES
}

func TestAuth429(t *testing.T) {
	ctx, apiKey, mockES := setup(t, http.StatusTooManyRequests)
	_, err := apiKey.Authenticate(ctx, mockES)

	assert.Equal(t, "elasticsearch auth limit: apikey auth response  foo: [429 Too Many Requests] ", err.Error())
}

func TestAuth401(t *testing.T) {
	ctx, apiKey, mockES := setup(t, http.StatusUnauthorized)
	_, err := apiKey.Authenticate(ctx, mockES)

	assert.Equal(t, "unauthorized: apikey auth response  foo: [401 Unauthorized] ", err.Error())
}

func TestAuthOtherErrors(t *testing.T) {
	scenarios := []struct {
		StatusCode int
	}{
		{StatusCode: http.StatusBadRequest},
		// 401 is handled in TestAuth401
		{StatusCode: http.StatusForbidden},
		{StatusCode: http.StatusNotFound},
		{StatusCode: http.StatusMethodNotAllowed},
		{StatusCode: http.StatusConflict},
		// 429 is handled in TestAuth429
		{StatusCode: http.StatusInternalServerError},
		{StatusCode: http.StatusBadGateway},
		{StatusCode: http.StatusServiceUnavailable},
		{StatusCode: http.StatusGatewayTimeout},
	}
	for _, scenario := range scenarios {
		t.Run(fmt.Sprintf("%d", scenario.StatusCode), func(t *testing.T) {
			ctx, apiKey, mockES := setup(t, scenario.StatusCode)
			_, err := apiKey.Authenticate(ctx, mockES)

			assert.Equal(t, fmt.Sprintf("elastic fail %d", scenario.StatusCode), err.Error())
		})
	}
}
