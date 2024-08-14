// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"

	"github.com/miolini/datacounter"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"
)

var ErrAuditUnenrollReason = fmt.Errorf("agent document contains audit_unenroll_reason attribute")

type AuditT struct {
	cfg   *config.Server
	bulk  bulk.Bulk
	cache cache.Cache
}

func NewAuditT(cfg *config.Server, bulker bulk.Bulk, cache cache.Cache) *AuditT {
	return &AuditT{
		cfg:   cfg,
		bulk:  bulker,
		cache: cache,
	}
}

func (audit *AuditT) handleUnenroll(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, id string) error {
	agent, err := authAgent(r, &id, audit.bulk, audit.cache)
	if err != nil {
		return err
	}
	zlog = zlog.With().Str(LogAccessAPIKeyID, agent.AccessAPIKeyID).Logger()
	ctx := zlog.WithContext(r.Context())
	r = r.WithContext(ctx)

	return audit.unenroll(zlog, w, r, agent)
}

func (audit *AuditT) unenroll(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, agent *model.Agent) error {
	if agent.AuditUnenrolledReason != "" {
		return ErrAuditUnenrollReason
	}

	req, err := audit.validateUnenrollRequest(zlog, w, r)
	if err != nil {
		return err
	}

	if err := audit.markUnenroll(r.Context(), zlog, req, agent); err != nil {
		return err
	}

	span, _ := apm.StartSpan(r.Context(), "response", "write")
	defer span.End()
	w.WriteHeader(http.StatusOK)
	return nil
}

func (audit *AuditT) validateUnenrollRequest(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request) (*AuditUnenrollRequest, error) {
	span, _ := apm.StartSpan(r.Context(), "validateRequest", "validate")
	defer span.End()

	body := r.Body
	if audit.cfg.Limits.AuditUnenrollLimit.MaxBody > 0 {
		body = http.MaxBytesReader(w, body, audit.cfg.Limits.AuditUnenrollLimit.MaxBody)
	}
	readCounter := datacounter.NewReaderCounter(body)

	var req AuditUnenrollRequest
	dec := json.NewDecoder(readCounter)
	if err := dec.Decode(&req); err != nil {
		return nil, &BadRequestErr{msg: "unable to decode audit/unenroll request", nextErr: err}
	}

	switch req.Reason {
	case Uninstall, Orphaned, KeyRevoked:
	default:
		return nil, &BadRequestErr{msg: "audit/unenroll request invalid reason"}
	}

	cntAuditUnenroll.bodyIn.Add(readCounter.Count())
	zlog.Trace().Msg("Audit unenroll request")
	return &req, nil
}

func (audit *AuditT) markUnenroll(ctx context.Context, zlog zerolog.Logger, req *AuditUnenrollRequest, agent *model.Agent) error {
	span, ctx := apm.StartSpan(ctx, "auditUnenroll", "process")
	defer span.End()

	now := time.Now().UTC().Format(time.RFC3339)
	doc := bulk.UpdateFields{
		dl.FieldUnenrolledAt:          now,
		dl.FieldUpdatedAt:             now,
		dl.FieldAuditUnenrolledTime:   req.Timestamp,
		dl.FieldAuditUnenrolledReason: req.Reason,
	}
	body, err := doc.Marshal()
	if err != nil {
		return fmt.Errorf("auditUnenroll marshal: %w", err)
	}

	if err := audit.bulk.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
		return fmt.Errorf("auditUnenroll update: %w", err)
	}

	zlog.Info().Msg("audit unenroll successful")
	return nil
}
