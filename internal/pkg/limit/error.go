// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package limit

import (
	"errors"
	"net/http"

	"github.com/rs/zerolog"
)

var (
	ErrRateLimit = errors.New("rate limit")
	ErrMaxLimit  = errors.New("max limit")
)

var (
	errBodyRateLimit = []byte(`{"statusCode":429,"error":"RateLimit","message":"exceeded the rate limit"}`)
	errBodyMaxLimit  = []byte(`{"statusCode":429,"error":"MaxLimit","message":"exceeded the max limit"}`)
	errBodyUnknown   = []byte(`{"statusCode":429,"error":"UnknownLimiterError","message":"unknown limiter error encountered"}`)
)

// writeError recreates the behaviour of api/error.go.
// It is defined separately here to stop a circular import
func writeError(log *zerolog.Logger, w http.ResponseWriter, err error) error {
	var body []byte
	switch {
	case errors.Is(err, ErrRateLimit):
		body = errBodyRateLimit
	case errors.Is(err, ErrMaxLimit):
		body = errBodyMaxLimit
	default:
		log.Error().Err(err).Msg("Encountered unknown limiter error")
		body = errBodyUnknown
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusTooManyRequests)
	_, wErr := w.Write(body)
	return wErr
}
