// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_Audit_validateUnenrollRequst(t *testing.T) {
	tests := []struct {
		name  string
		req   *http.Request
		cfg   *config.Server
		valid *AuditUnenrollRequest
		err   error
	}{{
		name: "ok",
		req: &http.Request{
			Body: io.NopCloser(strings.NewReader(`{"reason":"uninstall", "timestamp": "2024-01-01T12:00:00.000Z"}`)),
		},
		cfg: &config.Server{},
		valid: &AuditUnenrollRequest{
			Reason:    Uninstall,
			Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		err: nil,
	}, {
		name: "not json object",
		req: &http.Request{
			Body: io.NopCloser(strings.NewReader(`{"invalidJson":}`)),
		},
		cfg:   &config.Server{},
		valid: nil,
		err:   &BadRequestErr{msg: "unable to decode audit/unenroll request"},
	}, {
		name: "bad reason",
		req: &http.Request{
			Body: io.NopCloser(strings.NewReader(`{"reason":"bad reason", "timestamp": "2024-01-01T12:00:00.000Z"}`)),
		},
		cfg:   &config.Server{},
		valid: nil,
		err:   &BadRequestErr{msg: "audit/unenroll request invalid reason"},
	}, {
		name: "too large",
		req: &http.Request{
			Body: io.NopCloser(strings.NewReader(`{"reason":"uninstalled", "timestamp": "2024-01-01T12:00:00.000Z"}`)),
		},
		cfg: &config.Server{
			Limits: config.ServerLimits{
				AuditUnenrollLimit: config.Limit{
					MaxBody: 10,
				},
			},
		},
		valid: nil,
		err:   &BadRequestErr{msg: "unable to decode audit/unenroll request"},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			audit := AuditT{cfg: tc.cfg}
			w := httptest.NewRecorder()

			r, err := audit.validateUnenrollRequest(testlog.SetLogger(t), w, tc.req)
			if tc.err != nil {
				require.EqualError(t, err, tc.err.Error())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.valid, r)
		})
	}
}

func Test_Audit_markUnenroll(t *testing.T) {
	agent := &model.Agent{
		ESDocument: model.ESDocument{
			Id: "test-id",
		},
	}
	bulker := ftesting.NewMockBulk()
	bulker.On("Update", mock.Anything, dl.FleetAgents, agent.Id, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	audit := AuditT{bulk: bulker}
	logger := testlog.SetLogger(t)
	err := audit.markUnenroll(context.Background(), logger, &AuditUnenrollRequest{Reason: Uninstall, Timestamp: time.Now().UTC()}, agent)
	require.NoError(t, err)
	bulker.AssertExpectations(t)
}

func Test_Audit_unenroll(t *testing.T) {
	t.Run("agent has audit_unenroll_reason", func(t *testing.T) {
		agent := &model.Agent{
			AuditUnenrolledReason: string(Uninstall),
		}
		audit := &AuditT{}
		err := audit.unenroll(testlog.SetLogger(t), nil, nil, agent)
		require.EqualError(t, err, ErrAuditUnenrollReason.Error())
	})

	t.Run("ok", func(t *testing.T) {
		agent := &model.Agent{
			ESDocument: model.ESDocument{
				Id: "test-id",
			},
		}
		bulker := ftesting.NewMockBulk()
		bulker.On("Update", mock.Anything, dl.FleetAgents, agent.Id, mock.Anything, mock.Anything, mock.Anything).Return(nil)

		audit := &AuditT{
			bulk: bulker,
			cfg:  &config.Server{},
		}
		req := &http.Request{
			Body: io.NopCloser(strings.NewReader(`{"reason": "uninstall", "timestamp": "2024-01-01T12:00:00.000Z"}`)),
		}
		err := audit.unenroll(testlog.SetLogger(t), httptest.NewRecorder(), req, agent)
		require.NoError(t, err)
		bulker.AssertExpectations(t)
	})
}
