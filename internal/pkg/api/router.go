// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmhttprouter"
)

const (
	RouteStatus    = "/api/status"
	RouteEnroll    = "/api/fleet/agents/:id"
	RouteCheckin   = "/api/fleet/agents/:id/checkin"
	RouteAcks      = "/api/fleet/agents/:id/acks"
	RouteArtifacts = "/api/fleet/artifacts/:id/:sha2"
)

type Router struct {
	ctx    context.Context
	bulker bulk.Bulk
	ct     *CheckinT
	et     *EnrollerT
	at     *ArtifactT
	ack    *AckT
	st     *StatusT
	sm     policy.SelfMonitor
	bi     build.Info
}

func NewRouter(ctx context.Context, bulker bulk.Bulk, ct *CheckinT, et *EnrollerT, at *ArtifactT, ack *AckT, st *StatusT, sm policy.SelfMonitor, tracer *apm.Tracer, bi build.Info) *httprouter.Router {
	r := Router{
		ctx:    ctx,
		bulker: bulker,
		ct:     ct,
		et:     et,
		sm:     sm,
		at:     at,
		ack:    ack,
		st:     st,
		bi:     bi,
	}

	routes := []struct {
		method  string
		path    string
		handler httprouter.Handle
	}{
		{
			http.MethodGet,
			RouteStatus,
			r.handleStatus,
		},
		{
			http.MethodPost,
			RouteEnroll,
			r.handleEnroll,
		},
		{
			http.MethodPost,
			RouteCheckin,
			r.handleCheckin,
		},
		{
			http.MethodPost,
			RouteAcks,
			r.handleAcks,
		},
		{
			http.MethodGet,
			RouteArtifacts,
			r.handleArtifacts,
		},
	}

	router := httprouter.New()

	// Install routes
	for _, rte := range routes {
		log.Info().
			Str("method", rte.method).
			Str("path", rte.path).
			Msg("fleet-server route added")

		handler := rte.handler
		if tracer != nil {
			handler = apmhttprouter.Wrap(
				rte.handler, rte.path, apmhttprouter.WithTracer(tracer),
			)
		}
		router.Handle(
			rte.method,
			rte.path,
			logger.HttpHandler(handler),
		)
	}

	log.Info().Msg("fleet-server routes set up")

	return router
}
