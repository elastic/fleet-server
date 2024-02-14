package apikey

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
	"github.com/stretchr/testify/assert"
)

func TestAuth429(t *testing.T) {
	rawToken := " foo:bar"
	token := base64.StdEncoding.EncodeToString([]byte(rawToken))
	apiKey, err := NewAPIKeyFromToken(token)
	assert.NoError(t, err)
	ctx := context.Background()

	mockES, mockTransport := esutil.MockESClient(t)
	mockTransport.RoundTripFn = func(req *http.Request) (*http.Response, error) { return &http.Response{StatusCode: 429}, nil }

	_, err = apiKey.Authenticate(ctx, mockES)

	assert.Equal(t, "elasticsearch auth limit: apikey auth response  foo: [429 Too Many Requests] ", err.Error())
}

func TestAuth401(t *testing.T) {
	rawToken := " foo:bar"
	token := base64.StdEncoding.EncodeToString([]byte(rawToken))
	apiKey, err := NewAPIKeyFromToken(token)
	assert.NoError(t, err)
	ctx := context.Background()

	mockES, mockTransport := esutil.MockESClient(t)
	mockTransport.RoundTripFn = func(req *http.Request) (*http.Response, error) { return &http.Response{StatusCode: 401}, nil }

	_, err = apiKey.Authenticate(ctx, mockES)

	assert.Equal(t, "unauthorized: apikey auth response  foo: [401 Unauthorized] ", err.Error())
}
