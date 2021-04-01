// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package apikey

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMonitorLeadership(t *testing.T) {
	rawToken := " foo:bar"
	token := base64.StdEncoding.EncodeToString([]byte(rawToken))
	apiKey, err := NewApiKeyFromToken(token)
	assert.NoError(t, err)
	assert.Equal(t, *apiKey, ApiKey{" foo", "bar"})
	assert.Equal(t, token, apiKey.Token())
}
