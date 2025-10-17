// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gofrs/uuid/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	apmprometheus "go.elastic.co/apm/module/apmprometheus/v2"
	"go.elastic.co/apm/v2"

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
)

var (
	registry *metricsRegistry

	cntHTTPNew    *statsCounter
	cntHTTPClose  *statsCounter
	cntHTTPActive *statsGauge

	cntCheckin       routeStats
	cntEnroll        routeStats
	cntAcks          routeStats
	cntStatus        routeStats
	cntUploadStart   routeStats
	cntUploadChunk   routeStats
	cntUploadEnd     routeStats
	cntFileDeliv     routeStats
	cntGetPGP        routeStats
	cntAuditUnenroll routeStats
	cntArtifacts     artifactStats

	infoReg sync.Once
)

// init initializes all metrics that fleet-server collects
// metrics must be explicitly exposed with a call to InitMetrics
// FIXME we have global metrics but an internal and external API; this may lead to some confusion.
func init() {
	// maintain original behaviour from deprecated report.SetupMetrics
	ephemeralID, _ := uuid.NewV4()
	err := report.SetupMetricsOptions(report.MetricOptions{
		Name:           build.ServiceName,
		Version:        version.DefaultVersion,
		EphemeralID:    ephemeralID.String(),
		Logger:         logger.NewZapStub("instance-metrics"),
		SystemMetrics:  monitoring.Default.GetOrCreateRegistry("system"),
		ProcessMetrics: monitoring.Default.GetOrCreateRegistry("beat"),
	})

	if err != nil {
		zerolog.Ctx(context.TODO()).Error().Err(err).Msg("unable to initialize metrics") // TODO is used because this may logged during the package load
	}

	registry = newMetricsRegistry("http_server")
	cntHTTPNew = newCounter(registry, "tcp_open")
	cntHTTPClose = newCounter(registry, "tcp_close")
	cntHTTPActive = newGauge(registry, "tcp_active")

	routesRegistry := registry.newRegistry("routes")

	cntCheckin.Register(routesRegistry.newRegistry("checkin"))
	cntEnroll.Register(routesRegistry.newRegistry("enroll"))
	cntArtifacts.Register(routesRegistry.newRegistry("artifacts"))
	cntAcks.Register(routesRegistry.newRegistry("acks"))
	cntStatus.Register(routesRegistry.newRegistry("status"))
	cntUploadStart.Register(routesRegistry.newRegistry("uploadStart"))
	cntUploadChunk.Register(routesRegistry.newRegistry("uploadChunk"))
	cntUploadEnd.Register(routesRegistry.newRegistry("uploadEnd"))
	cntFileDeliv.Register(routesRegistry.newRegistry("deliverFile"))
	cntGetPGP.Register(routesRegistry.newRegistry("getPGPKey"))
	cntAuditUnenroll.Register(routesRegistry.newRegistry("auditUnenroll"))
}

// metricsRegistry wraps libbeat and prometheus registries
type metricsRegistry struct {
	fullName string
	registry *monitoring.Registry
	promReg  *prometheus.Registry
}

func newMetricsRegistry(name string) *metricsRegistry {
	reg := monitoring.Default
	return &metricsRegistry{
		fullName: name,
		registry: reg.GetOrCreateRegistry(name),
		promReg:  prometheus.NewRegistry(),
	}
}

func (r *metricsRegistry) newRegistry(name string) *metricsRegistry {
	fullName := name
	if r.fullName != "" {
		fullName = r.fullName + "_" + name
	}
	return &metricsRegistry{
		fullName: fullName,
		registry: r.registry.GetOrCreateRegistry(name),
		promReg:  r.promReg,
	}
}

// statsGauge wraps gauges for internal libbeat and prometheus
type statsGauge struct {
	metric *monitoring.Uint
	gauge  prometheus.Gauge
}

func newGauge(registry *metricsRegistry, name string) *statsGauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: registry.fullName,
		Name:      name,
	})
	registry.promReg.MustRegister(g)
	return &statsGauge{
		metric: monitoring.NewUint(registry.registry, name),
		gauge:  g,
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

// statsCounter wraps counters for internal libbeat and prometheus
type statsCounter struct {
	metric  *monitoring.Uint
	counter prometheus.Counter
}

func newCounter(registry *metricsRegistry, name string) *statsCounter {
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: registry.fullName,
		Name:      name,
	})
	registry.promReg.MustRegister(c)
	return &statsCounter{
		metric:  monitoring.NewUint(registry.registry, name),
		counter: c,
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

// routeStats is the generic collection metrics that we collect per API route.
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

// artifactStats is the collection of metrics we collect for the artifact route.
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

// InitMetrics initializes metrics exposure mechanisms.
// If tracer is not nil, prometheus metrics are shipped through the tracer.
// If cfg.http.enabled is true a /stats endpoint is created to expose libbeat metrics and a /metrics endpoint is created to expose prometheus metrics on the specified interface.
func InitMetrics(ctx context.Context, cfg *config.Config, bi build.Info, tracer *apm.Tracer) (*api.Server, error) {
	if tracer != nil {
		tracer.RegisterMetricsGatherer(apmprometheus.Wrap(registry.promReg))
	}

	reg := monitoring.GetNamespace("info").GetRegistry()
	if reg.Get("version") == nil {
		monitoring.NewString(reg, "version").Set(bi.Version)
	}
	if reg.Get("name") == nil {
		monitoring.NewString(reg, "name").Set(build.ServiceName)
	}

	if !cfg.HTTP.Enabled {
		return nil, nil
	}

	// Start local api server; largely for metrics.
	zapStub := logger.NewZapStub("fleet-metrics")
	cfgStub, err := cfglib.NewConfigFrom(&cfg.HTTP)
	if err != nil {
		return nil, err
	}
	s, err := api.NewWithDefaultRoutes(zapStub, cfgStub, monitoring.GetNamespace)
	if err != nil {
		return nil, fmt.Errorf("could not start the HTTP server for the API: %w", err)
	}

	attachPrometheusEndpoint(s, registry.promReg, bi)

	s.Start()
	return s, err
}

type metricsRouter interface {
	AddRoute(string, api.HandlerFunc)
}

func attachPrometheusEndpoint(router metricsRouter, reg *prometheus.Registry, bi build.Info) {
	// do not attempt to re-register the metric on metrics restart.
	// NOTE we may want to move this block earlier in InitMetrics so the tracer can ship it?
	infoReg.Do(func() {
		prometheusInfo := prometheus.NewCounter(prometheus.CounterOpts{
			Name: "service_info",
			Help: "Service information",
			ConstLabels: prometheus.Labels{
				"version": bi.Version,
				"name":    build.ServiceName,
			},
		})
		reg.MustRegister(prometheusInfo)
		prometheusInfo.Inc()
	})

	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	router.AddRoute("/metrics", promhttp.InstrumentMetricHandler(reg, h).ServeHTTP)
}
