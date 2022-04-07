// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

// Alias logger constants
const (
	EcsHTTPRequestID         = logger.EcsHttpRequestId
	EcsEventDuration         = logger.EcsEventDuration
	EcsHTTPResponseCode      = logger.EcsHttpResponseCode
	EcsHTTPResponseBodyBytes = logger.EcsHttpResponseBodyBytes

	LogAPIKeyID       = logger.ApiKeyId
	LogPolicyID       = logger.PolicyId
	LogAgentID        = logger.AgentId
	LogEnrollAPIKeyID = logger.EnrollApiKeyId
	LogAccessAPIKeyID = logger.AccessApiKeyId
)

// ErrResp is an HTTP error response
type ErrResp struct {
	StatusCode int           `json:"statusCode"`
	Error      string        `json:"error"`
	Message    string        `json:"message,omitempty"`
	Level      zerolog.Level `json:"-"`
}

// NewErrorResp creates an ErrResp from a go error
func NewErrorResp(err error) ErrResp {

	errTable := []struct {
		target error
		meta   ErrResp
	}{
		{
			ErrAgentNotFound,
			ErrResp{
				http.StatusNotFound,
				"AgentNotFound",
				"agent could not be found",
				zerolog.WarnLevel,
			},
		},
		{
			limit.ErrRateLimit,
			ErrResp{
				http.StatusTooManyRequests,
				"RateLimit",
				"exceeded the rate limit",
				zerolog.DebugLevel,
			},
		},
		{
			limit.ErrMaxLimit,
			ErrResp{
				http.StatusTooManyRequests,
				"MaxLimit",
				"exceeded the max limit",
				zerolog.DebugLevel,
			},
		},
		{
			ErrAPIKeyNotEnabled,
			ErrResp{
				http.StatusUnauthorized,
				"Unauthorized",
				"ApiKey not enabled",
				zerolog.InfoLevel,
			},
		},
		{
			context.Canceled,
			ErrResp{
				http.StatusServiceUnavailable,
				"ServiceUnavailable",
				"server is stopping",
				zerolog.DebugLevel,
			},
		},
		{
			ErrInvalidUserAgent,
			ErrResp{
				http.StatusBadRequest,
				"InvalidUserAgent",
				"user-agent is invalid",
				zerolog.InfoLevel,
			},
		},
		{
			ErrUnsupportedVersion,
			ErrResp{
				http.StatusBadRequest,
				"UnsupportedVersion",
				"version is not supported",
				zerolog.InfoLevel,
			},
		},
		{
			dl.ErrNotFound,
			ErrResp{
				http.StatusNotFound,
				"NotFound",
				"not found",
				zerolog.WarnLevel,
			},
		},
		{
			ErrorThrottle,
			ErrResp{
				http.StatusTooManyRequests,
				"TooManyRequests",
				"too many requests",
				zerolog.DebugLevel,
			},
		},
		{
			os.ErrDeadlineExceeded,
			ErrResp{
				http.StatusRequestTimeout,
				"RequestTimeout",
				"timeout on request",
				zerolog.InfoLevel,
			},
		},
	}

	for _, e := range errTable {
		if errors.Is(err, e.target) {
			return e.meta
		}
	}

	// Check if we have encountered a connectivity error
	// Predicate taken from https://github.com/golang/go/blob/go1.17.5/src/net/dial_test.go#L798
	if strings.Contains(err.Error(), "connection refused") {
		return ErrResp{
			http.StatusServiceUnavailable,
			"ServiceUnavailable",
			"Fleet server unable to communicate with Elasticsearch",
			zerolog.InfoLevel,
		}
	}

	// Default
	return ErrResp{
		StatusCode: http.StatusBadRequest,
		Error:      "BadRequest",
		Level:      zerolog.InfoLevel,
	}
}

// Write will serialize the ErrResp to an http response and include the proper headers.
func (er ErrResp) Write(w http.ResponseWriter) error {
	data, err := json.Marshal(&er)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(er.StatusCode)
	_, err = w.Write(data)
	return err
}
