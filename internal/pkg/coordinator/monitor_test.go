// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAvailabilityErrorNil(t *testing.T) {
	matched := isAvailabilityError(nil)
	assert.Equal(t, matched, false)
}

func TestIsAvailabilityErrorTimeout(t *testing.T) {
	matched := isAvailabilityError(errors.New("net/http: timeout awaiting response headers"))
	assert.Equal(t, matched, true)
}

func TestIsAvailabilityErrorConnectRefused(t *testing.T) {
	matched := isAvailabilityError(errors.New("dial tcp 127.0.0.1:9200: connect: connection refused"))
	assert.Equal(t, matched, true)
}

func TestIsAvailabilityErrorConnectRefusedRemote(t *testing.T) {
	matched := isAvailabilityError(errors.New("dial tcp 65.234.123:9200: connect: connection refused"))
	assert.Equal(t, matched, true)
}

func TestIsAvailabilityErrorUnhandledError(t *testing.T) {
	matched := isAvailabilityError(errors.New("novel error"))
	assert.Equal(t, matched, false)
}
