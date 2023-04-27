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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/version"
)

var (
	registry *metricsRegistry

	cntHTTPNew   *statsCounter
	cntHTTPClose *statsCounter

	cntCheckin     routeStats
	cntEnroll      routeStats
	cntAcks        routeStats
	cntStatus      routeStats
	cntUploadStart routeStats
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
		return nil, fmt.Errorf("could not start the HTTP server for the API: %w", err)
	}

	initPrometheusMetrics(s, bi)

	s.Start()
	return s, err
}

type metricsRouter interface {
	AddRoute(string, api.HandlerFunc)
}

func initPrometheusMetrics(router metricsRouter, bi build.Info) {
	prometheusInfo := promauto.NewCounter(prometheus.CounterOpts{
		Name: "service_info",
		Help: "Service information",
		ConstLabels: prometheus.Labels{
			"version": bi.Version,
			"name":    build.ServiceName,
		},
	})
	prometheusInfo.Inc()

	router.AddRoute("/metrics", promhttp.Handler().ServeHTTP)
}

type metricsRegistry struct {
	fullName string
	registry *monitoring.Registry
}

func newMetricsRegistry(name string) *metricsRegistry {
	def := metricsRegistry{registry: monitoring.Default}
	return def.newRegistry(name)
}

func (r *metricsRegistry) newRegistry(name string) *metricsRegistry {
	fullName := name
	if r.fullName != "" {
		fullName = r.fullName + "_" + name
	}
	return &metricsRegistry{
		fullName: fullName,
		registry: r.registry.NewRegistry(name),
	}
}

type statsGauge struct {
	metric *monitoring.Uint
	gauge  prometheus.Gauge
}

func newGauge(registry *metricsRegistry, name string) *statsGauge {
	return &statsGauge{
		metric: monitoring.NewUint(registry.registry, name),
		gauge: promauto.NewGauge(prometheus.GaugeOpts{
			Name: registry.fullName + "_" + name,
		}),
	}
}

func (g *statsGauge) Add(delta uint64) {
	g.metric.Add(delta)
	g.gauge.Add(float64(delta))
}

func (g *statsGauge) Inc() {
	g.metric.Inc()
	g.gauge.Inc()
}

func (g *statsGauge) Dec() {
	g.metric.Dec()
	g.gauge.Dec()
}

type statsCounter struct {
	metric  *monitoring.Uint
	counter prometheus.Counter
}

func newCounter(registry *metricsRegistry, name string) *statsCounter {
	return &statsCounter{
		metric: monitoring.NewUint(registry.registry, name),
		counter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: registry.fullName + "_" + name,
		}),
	}
}

func (g *statsCounter) Add(delta uint64) {
	g.metric.Add(delta)
	g.counter.Add(float64(delta))
}

func (g *statsCounter) Inc() {
	g.metric.Inc()
	g.counter.Inc()
}

type routeStats struct {
	active    *statsGauge
	total     *statsCounter
	rateLimit *statsCounter
	maxLimit  *statsCounter
	failure   *statsCounter
	drop      *statsCounter
	bodyIn    *statsCounter
	bodyOut   *statsCounter
}

func (rt *routeStats) Register(registry *metricsRegistry) {
	rt.active = newGauge(registry, "active")
	rt.total = newCounter(registry, "total")
	rt.rateLimit = newCounter(registry, "limit_rate")
	rt.maxLimit = newCounter(registry, "limit_max")
	rt.failure = newCounter(registry, "fail")
	rt.drop = newCounter(registry, "drop")
	rt.bodyIn = newCounter(registry, "body_in")
	rt.bodyOut = newCounter(registry, "body_out")
}

func init() {
	err := report.SetupMetrics(logger.NewZapStub("instance-metrics"), build.ServiceName, version.DefaultVersion)
	if err != nil {
		log.Error().Err(err).Msg("unable to initialize metrics")
	}

	registry = newMetricsRegistry("http_server")
	cntHTTPNew = newCounter(registry, "tcp_open")
	cntHTTPClose = newCounter(registry, "tcp_close")

	routesRegistry := registry.newRegistry("routes")

	cntCheckin.Register(routesRegistry.newRegistry("checkin"))
	cntEnroll.Register(routesRegistry.newRegistry("enroll"))
	cntArtifacts.Register(routesRegistry.newRegistry("artifacts"))
	cntAcks.Register(routesRegistry.newRegistry("acks"))
	cntStatus.Register(routesRegistry.newRegistry("status"))
	cntUploadStart.Register(routesRegistry.newRegistry("uploadStart"))
	cntUploadChunk.Register(routesRegistry.newRegistry("uploadChunk"))
	cntUploadEnd.Register(routesRegistry.newRegistry("uploadEnd"))
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
	notFound *statsCounter
	throttle *statsCounter
}

func (rt *artifactStats) Register(registry *metricsRegistry) {
	rt.routeStats.Register(registry)
	rt.notFound = newCounter(registry, "not_found")
	rt.throttle = newCounter(registry, "throttle")
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
