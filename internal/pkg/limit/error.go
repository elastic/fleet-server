// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limit

import (
	"encoding/json"
	"errors"
	"net/http"
)

var (
	ErrRateLimit = errors.New("rate limit")
	ErrMaxLimit  = errors.New("max limit")
)

// writeError recreates the behaviour of api/error.go
// it is defined separatly here to stop a circular import
func writeError(w http.ResponseWriter, err error) error {
	resp := struct {
		Status  int    `json:"statusCode"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}{
		Status:  http.StatusTooManyRequests,
		Error:   "UnknownLimiter",
		Message: "unknown limiter error encountered",
	}
	switch {
	case errors.Is(err, ErrRateLimit):
		resp.Error = "RateLimit"
		resp.Message = "exceeded the rate limit"
	case errors.Is(err, ErrMaxLimit):
		resp.Error = "MaxLimit"
		resp.Message = "exceeded the max limit"
	default:
	}
	p, wErr := json.Marshal(&resp)
	if wErr != nil {
		return wErr
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusTooManyRequests)
	_, wErr = w.Write(p)
	return wErr
}
