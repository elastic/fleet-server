// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/stretchr/testify/require"
	"go.elastic.co/apm/v2"
	"go.elastic.co/apm/v2/apmtest"
)

func Test_ErrorResp(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedTags map[string]interface{}
	}{{
		name: "generic error",
		err:  fmt.Errorf("generic error"),
	}, {
		name: "elastic error",
		err:  &es.ErrElastic{},
		expectedTags: map[string]interface{}{
			"error_type": "ErrElastic",
		},
	}, {
		name: "wrapped elastic error",
		err:  fmt.Errorf("wrapped error: %w", &es.ErrElastic{}),
		expectedTags: map[string]interface{}{
			"error_type": "ErrElastic",
		},
	}}

	tracer := apmtest.NewRecordingTracer()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := testlog.SetLogger(t)
			tracer.ResetPayloads()

			tx := tracer.StartTransaction("test", "test")
			ctx := apm.ContextWithTransaction(context.Background(), tx)
			ctx = logger.WithContext(ctx)

			wr := httptest.NewRecorder()
			req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost", nil)
			require.NoError(t, err)

			ErrorResp(wr, req, tc.err)
			tx.End()
			ch := make(chan struct{}, 1)
			tracer.Flush(ch)

			payloads := tracer.Payloads()
			require.Len(t, payloads.Transactions, 1)
			require.Len(t, payloads.Errors, 1)

			tags := make(map[string]interface{})
			for _, tag := range payloads.Transactions[0].Context.Tags {
				tags[tag.Key] = tag.Value
			}
			for k, v := range tc.expectedTags {
				require.Contains(t, tags, k, "expected tag is missing")
				require.Equal(t, v, tags[k], "expected tag value does not match")
			}
		})
	}
}

func Test_ErrorResp_NoTransaction(t *testing.T) {
	tracer := apmtest.NewRecordingTracer()
	ctx := testlog.SetLogger(t).WithContext(context.Background())

	wr := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost", nil)
	require.NoError(t, err)

	ErrorResp(wr, req, fmt.Errorf("some error"))
	ch := make(chan struct{}, 1)
	tracer.Flush(ch)

	payloads := tracer.Payloads()
	require.Len(t, payloads.Transactions, 0)
	require.Len(t, payloads.Errors, 0)
}

func Test_ErrResp_Status(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{{
		name:   "context canceled",
		err:    context.Canceled,
		status: 499,
	}, {
		name:   "generic error",
		err:    fmt.Errorf("some error"),
		status: 500,
	}, {
		name: "es error",
		err: &es.ErrElastic{
			Status: 500,
		},
		status: 503,
	}, {
		name: "decode req error",
		err: &BadRequestErr{
			msg:     "testMessage",
			nextErr: fmt.Errorf("testError"),
		},
		status: 400,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewHTTPErrResp(tc.err)
			require.Equal(t, tc.status, r.StatusCode)
		})
	}
}
