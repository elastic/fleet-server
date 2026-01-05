// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/rs/zerolog"
)

const (
	kOpAMPMod = "opAMP"
)

type OpAMPT struct {
	bulk  bulk.Bulk
	cache cache.Cache
}

func NewOpAMPT(bulker bulk.Bulk, cache cache.Cache) *OpAMPT {
	oa := &OpAMPT{
		bulk:  bulker,
		cache: cache,
	}
	return oa
}

func (oa OpAMPT) handleOpAMP(zlog zerolog.Logger, r *http.Request, w http.ResponseWriter) error {
	if _, err := authAPIKey(r, oa.bulk, oa.cache); err != nil {
		zlog.Debug().Err(err).Msg("unauthenticated opamp request")
		return err
	}

	return nil
}
