// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"

	"github.com/rs/zerolog"
)

const (
	kStatusMod = "status"
)

type AuthFunc func(*http.Request) (*apikey.APIKey, error)

type StatusT struct {
	cfg    *config.Server
	bulk   bulk.Bulk
	cache  cache.Cache
	authfn AuthFunc
}

type OptFunc func(*StatusT)

func NewStatusT(cfg *config.Server, bulker bulk.Bulk, cache cache.Cache, opts ...OptFunc) *StatusT {
	st := &StatusT{
		cfg:   cfg,
		bulk:  bulker,
		cache: cache,
	}
	st.authfn = st.authenticate

	for _, opt := range opts {
		opt(st)
	}
	return st
}

func (st StatusT) authenticate(r *http.Request) (*apikey.APIKey, error) {
	// This authenticates that the provided API key exists and is enabled.
	// WARNING: This does not validate that the api key is valid for the Fleet Domain.
	// An additional check must be executed to validate it is not a random api key.
	// This check is sufficient for the purposes of this API
	return authAPIKey(r, st.bulk, st.cache)
}

func (st StatusT) handleStatus(zlog zerolog.Logger, sm policy.SelfMonitor, bi build.Info, r *http.Request, w http.ResponseWriter) error {
	authed := true
	if _, aerr := st.authfn(r); aerr != nil {
		zlog.Debug().Err(aerr).Msg("unauthenticated status request, return short status response only")
		authed = false
	}

	state := sm.State()
	resp := StatusAPIResponse{
		Name:   build.ServiceName,
		Status: StatusResponseStatus(state.String()), // TODO try to make the oapi codegen less verbose here
	}

	if authed {
		bt := bi.BuildTime.Format(time.RFC3339)
		resp.Version = &StatusResponseVersion{
			Number:    &bi.Version,
			BuildHash: &bi.Commit,
			BuildTime: &bt,
		}
	}

	data, err := json.Marshal(&resp)
	if err != nil {
		return err
	}

	code := http.StatusServiceUnavailable
	if state == client.UnitStateHealthy {
		code = http.StatusOK
	}
	w.WriteHeader(code)

	ts, ok := logger.CtxStartTime(r.Context())
	nWritten, err := w.Write(data)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			e := zlog.Error().Err(err).Int(ECSHTTPResponseCode, code)
			if ok {
				e = e.Int64(ECSEventDuration, time.Since(ts).Nanoseconds())
			}
			e.Msg("fail status")
		}
	}

	cntStatus.bodyOut.Add(uint64(nWritten))
	e := zlog.Debug().Int(ECSHTTPResponseBodyBytes, nWritten)
	if ok {
		e = e.Int64(ECSEventDuration, time.Since(ts).Nanoseconds())
	}
	e.Msg("ok status")

	return nil
}
