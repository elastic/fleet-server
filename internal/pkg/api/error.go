// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/delivery"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/uploader"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

// Alias logger constants
const (
	ECSHTTPRequestID         = ecs.HTTPRequestID
	ECSEventDuration         = ecs.EventDuration
	ECSHTTPResponseCode      = ecs.HTTPResponseCode
	ECSHTTPResponseBodyBytes = ecs.HTTPResponseBodyBytes

	LogAPIKeyID       = ecs.APIKeyID
	LogPolicyID       = ecs.PolicyID
	LogAgentID        = ecs.AgentID
	LogEnrollAPIKeyID = ecs.EnrollAPIKeyID
	LogAccessAPIKeyID = ecs.AccessAPIKeyID
)

// BadRequestErr is used for request validation errors. These can be json
// unmarshal errors such as json.SyntaxError, or any other input validation
// error.
type BadRequestErr struct {
	msg     string
	nextErr error
}

func (e *BadRequestErr) Error() string {
	s := fmt.Sprintf("Bad request: %s", e.msg)
	if e.nextErr != nil {
		s += ": " + e.nextErr.Error()
	}
	return s
}

func (e *BadRequestErr) Unwrap() error {
	return e.nextErr
}

// HTTPErrResp is an HTTP error response
type HTTPErrResp struct {
	StatusCode int           `json:"statusCode"`
	Error      string        `json:"error"`
	Message    string        `json:"message,omitempty"`
	Level      zerolog.Level `json:"-"`
}

// NewHTTPErrResp creates an ErrResp from a go error
func NewHTTPErrResp(err error) HTTPErrResp {
	errTable := []struct {
		target error
		meta   HTTPErrResp
	}{
		{
			ErrAgentNotFound,
			HTTPErrResp{
				http.StatusNotFound,
				"AgentNotFound",
				"agent could not be found",
				zerolog.WarnLevel,
			},
		},
		{
			ErrAPIKeyNotEnabled,
			HTTPErrResp{
				http.StatusUnauthorized,
				"Unauthorized",
				"ApiKey not enabled",
				zerolog.InfoLevel,
			},
		},
		{
			context.Canceled,
			HTTPErrResp{
				499,
				"StatusClientClosedRequest",
				"server is stopping",
				zerolog.InfoLevel,
			},
		},
		{
			ErrAgentNotReplaceable,
			HTTPErrResp{
				http.StatusForbidden,
				"AgentNotReplaceable",
				"existing agent cannot be replaced",
				zerolog.WarnLevel,
			},
		},
		{
			ErrInvalidUserAgent,
			HTTPErrResp{
				http.StatusBadRequest,
				"InvalidUserAgent",
				"user-agent is invalid",
				zerolog.InfoLevel,
			},
		},
		{
			ErrUnsupportedVersion,
			HTTPErrResp{
				http.StatusBadRequest,
				"UnsupportedVersion",
				"version is not supported",
				zerolog.InfoLevel,
			},
		},
		{
			dl.ErrNotFound,
			HTTPErrResp{
				http.StatusNotFound,
				"NotFound",
				"not found",
				zerolog.WarnLevel,
			},
		},
		{
			ErrorThrottle,
			HTTPErrResp{
				http.StatusTooManyRequests,
				"TooManyRequests",
				"too many requests",
				zerolog.DebugLevel,
			},
		},
		{
			limit.ErrRateLimit,
			HTTPErrResp{
				http.StatusTooManyRequests,
				"RateLimit",
				"exceeded the rate limit",
				zerolog.WarnLevel,
			},
		},
		{
			limit.ErrMaxLimit,
			HTTPErrResp{
				http.StatusTooManyRequests,
				"MaxLimit",
				"exceeded the max limit",
				zerolog.WarnLevel,
			},
		},
		{
			apikey.ErrElasticsearchAuthLimit,
			HTTPErrResp{
				http.StatusTooManyRequests,
				"ElasticsearchAPIKeyAuthLimit",
				"exceeded the elasticsearch api key auth limit",
				zerolog.WarnLevel,
			},
		},
		{
			os.ErrDeadlineExceeded,
			HTTPErrResp{
				http.StatusRequestTimeout,
				"RequestTimeout",
				"timeout on request",
				zerolog.InfoLevel,
			},
		},
		{
			ErrUpdatingInactiveAgent,
			HTTPErrResp{
				http.StatusUnauthorized,
				"Unauthorized",
				"Agent not active",
				zerolog.InfoLevel,
			},
		},
		{
			ErrTransitHashRequired,
			HTTPErrResp{
				http.StatusBadRequest,
				"TransitHashRequired",
				"Transit hash required",
				zerolog.InfoLevel,
			},
		},
		{
			ErrAgentIdentity,
			HTTPErrResp{
				http.StatusForbidden,
				"ErrAgentIdentity",
				"Agent header contains wrong identifier",
				zerolog.InfoLevel,
			},
		},
		{
			ErrAgentCorrupted,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrAgentCorrupted",
				"Agent record corrupted",
				zerolog.InfoLevel,
			},
		},
		{
			ErrAgentInactive,
			HTTPErrResp{
				http.StatusUnauthorized,
				"ErrAgentInactive",
				"Agent inactive",
				zerolog.InfoLevel,
			},
		},
		{
			ErrAPIKeyNotEnabled,
			HTTPErrResp{
				http.StatusUnauthorized,
				"ErrAPIKeyNotEnabled",
				"APIKey not enabled",
				zerolog.InfoLevel,
			},
		},
		{
			ErrFileInfoBodyRequired,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrFileInfoBodyRequired",
				"file info body is required",
				zerolog.InfoLevel,
			},
		},
		{
			ErrAgentIDMissing,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrAgentIDMissing",
				"equired field agent_id is missing",
				zerolog.InfoLevel,
			},
		},
		{
			ErrTLSRequired,
			HTTPErrResp{
				http.StatusNotImplemented,
				"ErrTLSRequired",
				"server must run with tls to use this endpoint",
				zerolog.InfoLevel,
			},
		},
		// apikey
		{
			apikey.ErrNoAuthHeader,
			HTTPErrResp{
				http.StatusUnauthorized,
				"ErrNoAuthHeader",
				"no authorization header",
				zerolog.InfoLevel,
			},
		},
		{
			apikey.ErrMalformedHeader,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrMalformedHeader",
				"malformed authorization header",
				zerolog.InfoLevel,
			},
		},
		{
			apikey.ErrUnauthorized,
			HTTPErrResp{
				http.StatusUnauthorized,
				"ErrUnauthorized",
				"unauthorized",
				zerolog.InfoLevel,
			},
		},
		{
			apikey.ErrMalformedToken,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrMalformedToken",
				"malformed token",
				zerolog.InfoLevel,
			},
		},
		{
			apikey.ErrInvalidToken,
			HTTPErrResp{
				http.StatusUnauthorized,
				"ErrInvalidToken",
				"token not valid utf8",
				zerolog.InfoLevel,
			},
		},
		{
			apikey.ErrAPIKeyNotFound,
			HTTPErrResp{
				http.StatusUnauthorized,
				"ErrAPIKeyNotFound",
				"api key not found",
				zerolog.InfoLevel,
			},
		},
		// upload
		{
			uploader.ErrInvalidUploadID,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrAPIKeyNotFound",
				"active upload not found with this ID, it may be expired",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrFileSizeTooLarge,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrFileSizeTooLarge",
				"this file exceeds the maximum allowed file size",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrMissingChunks,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrMissingChunks",
				"file data incomplete, not all chunks were uploaded",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrHashMismatch,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrHashMismatch",
				"hash does not match",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrUploadExpired,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrUploadExpired",
				"upload has expired",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrUploadStopped,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrUploadStopped",
				"upload has stopped",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrInvalidChunkNum,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrInvalidChunkNum",
				"invalid chunk number",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrFailValidation,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrFailValidation",
				"file contents failed validation",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrStatusNoUploads,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrStatusNoUploads",
				"file closed, not accepting uploads",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrPayloadRequired,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrPayloadRequired",
				"upload start payload required",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrFileSizeRequired,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrFileSizeRequired",
				"file.size is required",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrInvalidFileSize,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrInvalidFileSize",
				"",
				zerolog.InfoLevel,
			},
		},
		{
			uploader.ErrFieldRequired,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrFieldRequired",
				"",
				zerolog.InfoLevel,
			},
		},
		// Version
		{
			ErrInvalidAPIVersionFormat,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrInvalidAPIVersionFormat",
				"",
				zerolog.InfoLevel,
			},
		},
		{
			ErrUnsupportedAPIVersion,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrUnsupportedAPIVersion",
				"",
				zerolog.InfoLevel,
			},
		},
		// file
		{
			delivery.ErrNoFile,
			HTTPErrResp{
				http.StatusNotFound,
				"ErrNoFile",
				"file not found",
				zerolog.InfoLevel,
			},
		},
		{
			file.ErrInvalidID,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrInvalidFileID",
				"ErrInvalidID",
				zerolog.InfoLevel,
			},
		},
		{
			ErrPolicyNotFound,
			HTTPErrResp{
				http.StatusBadRequest,
				"ErrPolicyNotFound",
				"ErrPolicyNotFound",
				zerolog.InfoLevel,
			},
		},
		// audit unenroll
		{
			ErrAuditUnenrollReason,
			HTTPErrResp{
				http.StatusConflict,
				"ErrAuditReasonConflict",
				"agent document contains audit_unenroll_reason",
				zerolog.InfoLevel,
			},
		},
		{
			target: uploader.ErrPayloadSizeTooLarge,
			meta: HTTPErrResp{
				StatusCode: http.StatusRequestEntityTooLarge,
				Error:      "ErrPayloadSizeTooLarge",
				Message:    "the request body exceeds the maximum allowed size",
				Level:      zerolog.InfoLevel,
			},
		},
	}

	for _, e := range errTable {
		if errors.Is(err, e.target) {
			if len(e.meta.Message) == 0 {
				return HTTPErrResp{
					e.meta.StatusCode,
					e.meta.Error,
					err.Error(),
					e.meta.Level,
				}
			}

			return e.meta
		}
	}

	var drErr *BadRequestErr
	if errors.As(err, &drErr) {
		return HTTPErrResp{
			http.StatusBadRequest,
			"BadRequest",
			err.Error(),
			zerolog.ErrorLevel,
		}
	}

	// If it's a JSON marshal error
	var jErr *json.MarshalerError
	if errors.As(err, &jErr) {
		return HTTPErrResp{
			http.StatusInternalServerError,
			err.Error(),
			"Fleet server unable to marshall JSON",
			zerolog.ErrorLevel,
		}
	}

	var esErr *es.ErrElastic
	if errors.As(err, &esErr) {
		return HTTPErrResp{
			http.StatusServiceUnavailable,
			esErr.Error(),
			"elasticsearch error",
			zerolog.ErrorLevel,
		}
	}

	// Check if we have encountered a connectivity error
	// Predicate taken from https://github.com/golang/go/blob/go1.17.5/src/net/dial_test.go#L798
	if strings.Contains(err.Error(), "connection refused") {
		return HTTPErrResp{
			http.StatusServiceUnavailable,
			"ServiceUnavailable",
			"Fleet server unable to communicate with Elasticsearch",
			zerolog.InfoLevel,
		}
	}

	// Default
	return HTTPErrResp{
		StatusCode: http.StatusInternalServerError,
		Error:      "BadRequest",
		Message:    err.Error(),
		Level:      zerolog.InfoLevel,
	}
}

// Write will serialize the ErrResp to an http response and include the proper headers.
func (er HTTPErrResp) Write(w http.ResponseWriter) error {
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

func ErrorResp(w http.ResponseWriter, r *http.Request, err error) {
	zlog := hlog.FromRequest(r)
	resp := NewHTTPErrResp(err)
	e := zlog.WithLevel(resp.Level).Err(err).Int(ECSHTTPResponseCode, resp.StatusCode).Str("error.type", fmt.Sprintf("%T", err))
	if ts, ok := logger.CtxStartTime(r.Context()); ok {
		e = e.Int64(ECSEventDuration, time.Since(ts).Nanoseconds())
	}
	e.Msg("HTTP request error")

	if resp.StatusCode >= 500 {
		if trans := apm.TransactionFromContext(r.Context()); trans != nil {
			esErr := &es.ErrElastic{}
			if errors.As(err, &esErr) {
				trans.Context.SetLabel("error.type", "ErrElastic")
				trans.Context.SetLabel("error.details.status", esErr.Status)
				trans.Context.SetLabel("error.details.type", esErr.Type)
				trans.Context.SetLabel("error.details.reason", esErr.Reason)
				trans.Context.SetLabel("error.details.cause.type", esErr.Cause.Type)
				trans.Context.SetLabel("error.details.cause.reason", esErr.Cause.Reason)
			} else {
				trans.Context.SetLabel("error.type", fmt.Sprintf("%T", err))
			}
		}
		apm.CaptureError(r.Context(), err).Send()
	}

	if rerr := resp.Write(w); rerr != nil {
		zlog.Error().Err(rerr).Msg("fail writing error response")
	}
}
