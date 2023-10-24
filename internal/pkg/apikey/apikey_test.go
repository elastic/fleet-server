// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package apikey

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMonitorLeadership(t *testing.T) {
	rawToken := " foo:bar"
	token := base64.StdEncoding.EncodeToString([]byte(rawToken))
	apiKey, err := NewAPIKeyFromToken(token)
	assert.NoError(t, err)
	assert.Equal(t, *apiKey, APIKey{" foo", "bar"})
	assert.Equal(t, token, apiKey.Token())
}

func TestNewAPIKeyFromToken(t *testing.T) {
	tests := []struct {
		name        string
		apiKey      string
		expectError error
	}{{
		name:        "Invalid base64",
		apiKey:      "invalidbase64",
		expectError: ErrInvalidToken,
	},
		{
			name:        "malformed token",
			apiKey:      "dGVzdA==",
			expectError: ErrMalformedToken,
		},
		{
			name:        "Invalid utf8",
			apiKey:      "dGVzdMlA",
			expectError: ErrInvalidToken,
		},
		{
			name:        "Valid api key",
			apiKey:      "bURmODBZb0JrTU82QzJJaVVET1A6bmVRUnBsWEJRbmVTVFIwV3FtaVVFZw==",
			expectError: nil,
		}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAPIKeyFromToken(tc.apiKey)
			if tc.expectError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tc.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
