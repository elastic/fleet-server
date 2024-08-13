// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"errors"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/rs/zerolog"
)

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
	return errors.ErrUnsupported
}
