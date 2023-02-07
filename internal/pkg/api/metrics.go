// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent-libs/api"
	cfglib "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent-system-metrics/report"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/version"

	"github.com/rs/zerolog/log"
)

var (
	registry *monitoring.Registry

	cntHTTPNew   *monitoring.Uint
	cntHTTPClose *monitoring.Uint

	cntCheckin     routeStats
	cntEnroll      routeStats
	cntAcks        routeStats
	cntStatus      routeStats
	cntUpload      routeStats
	cntUploadChunk routeStats
	cntUploadEnd   routeStats
	cntArtifacts   artifactStats
)

func InitMetrics(ctx context.Context, cfg *config.Config, bi build.Info) (*api.Server, error) {
	registry := monitoring.GetNamespace("info").GetRegistry()
	if registry.Get("version") == nil {
		monitoring.NewString(registry, "version").Set(bi.Version)
	}
	if registry.Get("name") == nil {
		monitoring.NewString(registry, "name").Set(build.ServiceName)
	}

	if !cfg.HTTP.Enabled {
		return nil, nil
	}

	// Start local api server; largely for metics.
	zapStub := logger.NewZapStub("fleet-metrics")
	cfgStub, err := cfglib.NewConfigFrom(&cfg.HTTP)
	if err != nil {
		return nil, err
	}
	s, err := api.NewWithDefaultRoutes(zapStub, cfgStub, monitoring.GetNamespace)
	if err != nil {
		err = fmt.Errorf("could not start the HTTP server for the API: %w", err)
	} else {
		s.Start()
	}

	return s, err
}

type routeStats struct {
	active    *monitoring.Uint
	total     *monitoring.Uint
	rateLimit *monitoring.Uint
	maxLimit  *monitoring.Uint
	failure   *monitoring.Uint
	drop      *monitoring.Uint
	bodyIn    *monitoring.Uint
	bodyOut   *monitoring.Uint
}

func (rt *routeStats) Register(registry *monitoring.Registry) {
	rt.active = monitoring.NewUint(registry, "active")
	rt.total = monitoring.NewUint(registry, "total")
	rt.rateLimit = monitoring.NewUint(registry, "limit_rate")
	rt.maxLimit = monitoring.NewUint(registry, "limit_max")
	rt.failure = monitoring.NewUint(registry, "fail")
	rt.drop = monitoring.NewUint(registry, "drop")
	rt.bodyIn = monitoring.NewUint(registry, "body_in")
	rt.bodyOut = monitoring.NewUint(registry, "body_out")
}

func init() {
	err := report.SetupMetrics(logger.NewZapStub("instance-metrics"), build.ServiceName, version.DefaultVersion)
	if err != nil {
		log.Error().Err(err).Msg("unable to initialize metrics")
	}

	registry = monitoring.Default.NewRegistry("http_server")
	cntHTTPNew = monitoring.NewUint(registry, "tcp_open")
	cntHTTPClose = monitoring.NewUint(registry, "tcp_close")

	routesRegistry := registry.NewRegistry("routes")

	cntCheckin.Register(routesRegistry.NewRegistry("checkin"))
	cntEnroll.Register(routesRegistry.NewRegistry("enroll"))
	cntArtifacts.Register(routesRegistry.NewRegistry("artifacts"))
	cntAcks.Register(routesRegistry.NewRegistry("acks"))
	cntStatus.Register(routesRegistry.NewRegistry("status"))
	cntUpload.Register(routesRegistry.NewRegistry("upload"))
	cntUploadChunk.Register(routesRegistry.NewRegistry("uploadChunk"))
	cntUploadEnd.Register(routesRegistry.NewRegistry("uploadEnd"))
}

func (rt *routeStats) IncError(err error) {

	switch {
	case errors.Is(err, limit.ErrRateLimit):
		rt.rateLimit.Inc()
	case errors.Is(err, limit.ErrMaxLimit):
		rt.maxLimit.Inc()
	case errors.Is(err, context.Canceled):
		rt.drop.Inc()
	default:
		rt.failure.Inc()
	}
}

func (rt *routeStats) IncStart() func() {
	rt.total.Inc()
	rt.active.Inc()
	return rt.active.Dec
}

type artifactStats struct {
	routeStats
	notFound *monitoring.Uint
	throttle *monitoring.Uint
}

func (rt *artifactStats) Register(registry *monitoring.Registry) {
	rt.routeStats.Register(registry)
	rt.notFound = monitoring.NewUint(registry, "not_found")
	rt.throttle = monitoring.NewUint(registry, "throttle")
}

func (rt *artifactStats) IncError(err error) {
	switch {
	case errors.Is(err, dl.ErrNotFound):
		rt.notFound.Inc()
	case errors.Is(err, ErrorThrottle):
		rt.throttle.Inc()
	default:
		rt.routeStats.IncError(err)
	}
}
