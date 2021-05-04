// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"github.com/pkg/errors"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"

	"github.com/elastic/beats/v7/libbeat/api"
	"github.com/elastic/beats/v7/libbeat/cmd/instance/metrics"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/monitoring"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/rs/zerolog"
)

var (
	registry *monitoring.Registry

	cntHttpNew   *monitoring.Uint
	cntHttpClose *monitoring.Uint

	cntCheckin   routeStats
	cntEnroll    routeStats
	cntAcks      routeStats
	cntStatus    routeStats
	cntArtifacts artifactStats
)

func (f *FleetServer) initMetrics(ctx context.Context, cfg *config.Config) (*api.Server, error) {
	registry := monitoring.GetNamespace("info").GetRegistry()
	if registry.Get("version") == nil {
		monitoring.NewString(registry, "version").Set(f.ver)
	}
	if registry.Get("name") == nil {
		monitoring.NewString(registry, "name").Set("fleet-server")
	}

	if !cfg.HTTP.Enabled {
		return nil, nil
	}

	// Start local api server; largely for metics.
	zapStub := logger.NewZapStub("fleet-metrics")
	cfgStub, err := common.NewConfigFrom(&cfg.HTTP)
	if err != nil {
		return nil, err
	}
	s, err := api.NewWithDefaultRoutes(zapStub, cfgStub, monitoring.GetNamespace)
	if err != nil {
		err = errors.Wrap(err, "could not start the HTTP server for the API")
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
	metrics.SetupMetrics("fleet-server")
	registry = monitoring.Default.NewRegistry("http_server")
	cntHttpNew = monitoring.NewUint(registry, "tcp_open")
	cntHttpClose = monitoring.NewUint(registry, "tcp_close")

	routesRegistry := registry.NewRegistry("routes")

	cntCheckin.Register(routesRegistry.NewRegistry("checkin"))
	cntEnroll.Register(routesRegistry.NewRegistry("enroll"))
	cntArtifacts.Register(routesRegistry.NewRegistry("artifacts"))
	cntAcks.Register(routesRegistry.NewRegistry("acks"))
	cntStatus.Register(routesRegistry.NewRegistry("status"))
}

// Increment error metric, log and return code
func (rt *routeStats) IncError(err error) (int, string, zerolog.Level) {
	lvl := zerolog.DebugLevel

	incFail := true

	var code int
	var errStr string
	switch err {
	case ErrAgentNotFound:
		errStr = "AgentNotFound"
		code = http.StatusNotFound
		lvl = zerolog.WarnLevel
	case limit.ErrRateLimit:
		errStr = "RateLimit"
		code = http.StatusTooManyRequests
		rt.rateLimit.Inc()
		incFail = false
	case limit.ErrMaxLimit:
		errStr = "MaxLimit"
		code = http.StatusTooManyRequests
		rt.maxLimit.Inc()
		incFail = false
	case context.Canceled:
		errStr = "ServiceUnavailable"
		code = http.StatusServiceUnavailable
		rt.drop.Inc()
		incFail = false
	default:
		errStr = "BadRequest"
		lvl = zerolog.InfoLevel
		code = http.StatusBadRequest
	}

	if incFail {
		cntCheckin.failure.Inc()
	}

	return code, errStr, lvl
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

func (rt *artifactStats) IncError(err error) (code int, str string, lvl zerolog.Level) {
	switch err {
	case dl.ErrNotFound:
		// Artifact not found indicates a race condition upstream
		// or an attack on the fleet server.  Either way it should
		// show up in the logs at a higher level than debug
		code = http.StatusNotFound
		str = "NotFound"
		rt.notFound.Inc()
		lvl = zerolog.WarnLevel
	case ErrorThrottle:
		code = http.StatusTooManyRequests
		str = "TooManyRequests"
		rt.throttle.Inc()
	default:
		code, str, lvl = rt.routeStats.IncError(err)
	}

	return
}
