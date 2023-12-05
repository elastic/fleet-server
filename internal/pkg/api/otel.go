// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog"

	"go.elastic.co/apm/module/apmotel/v2"
	"go.elastic.co/apm/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// otel metrics collection
// Metrics will be tied to the process lifecycle, it should be possible to reconfigure+restart the API server without restting metrics.
// We assume that something will call InitOTEL at least once, and shutdown the MeterProvider when the process is terminating.
//
// res, exp, provider, and meter are all inialized by InitOtel once.
// exp may be used as a source for the APM tracer in later calls (in case the tracer is reconfigured).
//
// metrics and routeStats should use Meter to create or retrieve metrics based off metric names.
var (
	otelInit sync.Once
	initTS   time.Time
	eID      string
	res      *resource.Resource
	exp      apmotel.Gatherer
	provider *sdkmetric.MeterProvider
	meter    metric.Meter

	countHTTPNew      metric.Int64Counter
	countHTTPClose    metric.Int64Counter
	upDownHTTPActive  metric.Int64UpDownCounter
	checkinStats      routeStats
	enrollStats       routeStats
	acksStats         routeStats
	statusStats       routeStats
	uploadStartStats  routeStats
	uploadChunkStats  routeStats
	uploadEndStats    routeStats
	fileDeliveryStats routeStats
	getPGPStats       routeStats
	artifactsStats    routeStats
)

// routeStats is a collection of otel metrics about each route
type routeStats struct {
	active   metric.Int64UpDownCounter
	total    metric.Int64Counter
	errCount metric.Int64Counter
	bodyIn   metric.Int64Counter
	bodyOut  metric.Int64Counter
}

// newRouteStats creates a new routeStats object where metric names are prefixed by the route name.
func newRouteStats(route string) (routeStats, error) {
	active, err := meter.Int64UpDownCounter(route+"_active", metric.WithDescription("Number of active HTTP requests."))
	if err != nil {
		return routeStats{}, err
	}
	total, err := meter.Int64Counter(route+"_total", metric.WithDescription("Total number of HTTP requests."))
	if err != nil {
		return routeStats{}, err
	}
	errCount, err := meter.Int64Counter(route+"_error", metric.WithDescription("Total number of errors for the route."))
	if err != nil {
		return routeStats{}, err
	}
	bodyIn, err := meter.Int64Counter(route+"_body_in", metric.WithDescription("Sum size of HTTP request bodies."), metric.WithUnit("By"))
	if err != nil {
		return routeStats{}, err
	}
	bodyOut, err := meter.Int64Counter(route+"_body_out", metric.WithDescription("Sum size of HTTP response bodies."), metric.WithUnit("By"))
	if err != nil {
		return routeStats{}, err
	}

	return routeStats{
		active:   active,
		total:    total,
		errCount: errCount,
		bodyIn:   bodyIn,
		bodyOut:  bodyOut,
	}, nil
}

// IncError adds to the route's error count with a custom error_type attribute set based on the passed error.
// Optional attribute.KeyValues may be sent as well, these can be used to indicate things like the server address.
func (r *routeStats) IncError(err error, kvs ...attribute.KeyValue) {
	switch {
	case errors.Is(err, dl.ErrNotFound):
		kvs = append(kvs, attribute.String("error_type", "not_found"))
	case errors.Is(err, ErrorThrottle):
		kvs = append(kvs, attribute.String("error_type", "throttle"))
	case errors.Is(err, limit.ErrRateLimit):
		kvs = append(kvs, attribute.String("error_type", "limit_rate"))
	case errors.Is(err, limit.ErrMaxLimit):
		kvs = append(kvs, attribute.String("error_type", "limit_max"))
	case errors.Is(err, context.Canceled):
		kvs = append(kvs, attribute.String("error_type", "drop"))
	default:
		kvs = append(kvs, attribute.String("error_type", "fail"))
	}
	ms := attribute.NewSet(kvs...)
	r.errCount.Add(context.TODO(), 1, metric.WithAttributeSet(ms))
}

// IncStart is a convience wrapper to call when a route handler has started.
// It increments the active and total counts for the route by one and returns a function that decrements the active count by one.
// Optional attribute.KeyValues may be specified, thes can be used to indicate things like the sever address.
func (r *routeStats) IncStart(kvs ...attribute.KeyValue) func() {
	ctx := context.TODO()
	ms := attribute.NewSet(kvs...)
	r.active.Add(ctx, 1, metric.WithAttributeSet(ms))
	r.total.Add(ctx, 1, metric.WithAttributeSet(ms))
	return func() {
		r.active.Add(ctx, -1, metric.WithAttributeSet(ms))
	}
}

// serverAttrs returns attributes that describe the server
func serverAttrs(u *url.URL) []attribute.KeyValue {
	port := u.Port()
	n, _ := strconv.Atoi(port)
	return []attribute.KeyValue{
		semconv.ServerAddress(u.Hostname()),
		semconv.ServerPort(n),
	}
}

// OTELWrapper is a convenience wrapper that can be used to shutdown OTEL collection and the beat metric server independently.
type OTELWrapper struct {
	server   *http.Server
	exporter *beatExporter
}

// newOTELWrapper returrns a new otelWrapper with a server that is not running
func newOTELWrapper(cfg config.HTTP, exporter *beatExporter) *OTELWrapper {
	if !cfg.Enabled {
		return &OTELWrapper{
			exporter: exporter,
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/stats", exporter)

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           mux,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      time.Minute,
		IdleTimeout:       30 * time.Second,
	}

	return &OTELWrapper{
		server:   server,
		exporter: exporter,
	}
}

// Start starts the HTTP metricbeat stats server if enabled and return any non http.ErrServerClosed errors.
func (o *OTELWrapper) Start() error {
	if o.server == nil {
		return nil
	}
	err := o.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown halts the metricbeat stats server.
func (o *OTELWrapper) Shutdown(ctx context.Context) error {
	if o.server == nil {
		return nil
	}
	return o.server.Shutdown(ctx)
}

// ShutdownProvider is a wrapper to shutdown the global otel.MeterProvider
// It should only be called once before process termination.
func (o *OTELWrapper) ShutdownProvider(ctx context.Context) error {
	if provider == nil {
		return nil
	}
	return provider.Shutdown(ctx)
}

// InitOTEL inializes otel resources using the APM exporter bridge and returns the OTEL wrapper.
// May panic if it is unable to create the otel resource.
// OTELWrapper.Start and OTELWrapper.Shutdown are  used to manage the HTTP metricbeat stats server lifecycle.
// OTELWrapper.ShutdownProvider should be called when the process is being halted.
func InitOTEL(info build.Info, tracer *apm.Tracer, cfg config.HTTP) (*OTELWrapper, error) {
	var err error
	otelInit.Do(func() {
		initTS = time.Now().UTC()
		eID = uuid.Must(uuid.NewV4()).String()

		res, err = resource.Merge(resource.Default(),
			resource.NewWithAttributes(semconv.SchemaURL,
				semconv.ServiceName("fleet-server"),
				semconv.ServiceVersion(info.Version),
				semconv.ServiceInstanceID(eID), // Set the ServiceInstanceID to the ephemeral ID
			))
		if err != nil {
			panic(err)
		}

		// NOTE: we are forcing cumulative temporality so se can call exp.Collect in order to expose metrics for metricbeat
		// Once this translation is no longer needed we can remove the option.
		exp, err = apmotel.NewGatherer(apmotel.WithTemporalitySelector(func(sdkmetric.InstrumentKind) metricdata.Temporality { return metricdata.CumulativeTemporality }))
		if err != nil {
			panic(err)
		}
		provider = sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(exp),
		)
		otel.SetMeterProvider(provider)
		meter = provider.Meter("fleet-server")
	})

	be := &beatExporter{
		gatherer:    exp,
		httpEnabled: cfg.Enabled,
	}

	// Link metrics to agent
	if tracer != nil {
		tracer.RegisterMetricsGatherer(be)
	}

	// Create all metrics
	countHTTPNew, err = meter.Int64Counter("tcp_open", metric.WithDescription("Number of TCP connections started."))
	if err != nil {
		return nil, err
	}
	countHTTPClose, err = meter.Int64Counter("tcp_close", metric.WithDescription("Number of TCP connections closed."))
	if err != nil {
		return nil, err
	}
	upDownHTTPActive, err = meter.Int64UpDownCounter("tcp_active", metric.WithDescription("Number of active TCP connections."))
	if err != nil {
		return nil, err
	}
	checkinStats, err = newRouteStats("checkin")
	if err != nil {
		return nil, err
	}
	enrollStats, err = newRouteStats("enroll")
	if err != nil {
		return nil, err
	}
	acksStats, err = newRouteStats("acks")
	if err != nil {
		return nil, err
	}
	statusStats, err = newRouteStats("status")
	if err != nil {
		return nil, err
	}
	uploadStartStats, err = newRouteStats("uploadStart")
	if err != nil {
		return nil, err
	}
	uploadChunkStats, err = newRouteStats("uploadChunk")
	if err != nil {
		return nil, err
	}
	uploadEndStats, err = newRouteStats("uploadEnd")
	if err != nil {
		return nil, err
	}
	fileDeliveryStats, err = newRouteStats("deliverFile")
	if err != nil {
		return nil, err
	}
	getPGPStats, err = newRouteStats("getPGPKey")
	if err != nil {
		return nil, err
	}
	artifactsStats, err = newRouteStats("artifact")
	if err != nil {
		return nil, err
	}

	return newOTELWrapper(cfg, be), nil
}

/*
 * Everything below is used to transform and expose otel metrics on an HTTP endpoint that can be consumed by Metricbeat
 * This is intended as a temporary solution to allow the elastic-agent to monitor fleet-server until elastic-agent supports monitoring it's components with otel directly.
 */

// BeatStats is the top-level response body for the stats endpoint Metricbeat reads.
type BeatStats struct {
	HTTPServer BeatHTTPStats `json:"http_server"`
	Beat       Beat          `json:"beat"`
}

// Beat describes fleet-server as a beat.
type Beat struct {
	Info BeatInfo `json:"info"`
}

// BeatInfo has information unique to fleet-server including a process-specific ephemeral_id.
type BeatInfo struct {
	EphemeralID string `json:"ephemeral_id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Uptime      struct {
		MS int64 `json:"ms"`
	} `json:"uptime"`
}

// BeatHTTPStats are the fleet-server's specific HTTP stats
type BeatHTTPStats struct {
	Routes    BeatRoutes `json:"routes"`
	TCPActive int64      `json:"tcp_active"`
	TCPClose  int64      `json:"tcp_close"`
	TCPOpen   int64      `json:"tcp_open"`
}

// BeatRoutes contains all the BeatRouteStats for the fleet-server's endpoints.
type BeatRoutes struct {
	Acks        BeatRouteStats `json:"acks"`
	Artifacts   BeatRouteStats `json:"artifacts"`
	Checkin     BeatRouteStats `json:"checkin"`
	DeliverFile BeatRouteStats `json:"deliverFile"`
	Enroll      BeatRouteStats `json:"enroll"`
	GetPGPKey   BeatRouteStats `json:"getPGPKey"`
	Status      BeatRouteStats `json:"status"`
	UploadChunk BeatRouteStats `json:"uploadChunk"`
	UploadEnd   BeatRouteStats `json:"uploadEnd"`
	UploadStart BeatRouteStats `json:"uploadStart"`
}

// BeatRouteStats contains all stats about a specific route on the fleet-server.
type BeatRouteStats struct {
	Active    int64 `json:"active"`
	BodyIn    int64 `json:"body_in"`
	BodyOut   int64 `json:"body_out"`
	Drop      int64 `json:"drop"`
	Fail      int64 `json:"fail"`
	LimitMax  int64 `json:"limit_max"`
	LimitRate int64 `json:"limit_rate"`
	Total     int64 `json:"total"`
	NotFound  int64 `json:"not_found,omitempty"` // May be empty as it's only used for the Artifacts endpoint
	Throttle  int64 `json:"throttle,omitempty"`  // May be empty as it's only used for the Artifacts endpoint
}

// fromMetricData sets BeatRouteStats to the sum of the metric data that is passed
// This is to merge datapoints with different attributes, or seprate them based on error_type to populate error output.
func (r *BeatRouteStats) fromMetricData(mType string, data metricdata.Aggregation) {
	switch mType {
	case "active":
		r.Active = sumMetricData(data)
	case "total":
		r.Total = sumMetricData(data)
	case "body_in":
		r.BodyIn = sumMetricData(data)
	case "body_out":
		r.BodyOut = sumMetricData(data)
	case "error":
		r.sumErrorData(data)
	default:
	}
}

// sumErrorData populates route error stats based on the error_type attribute of a [route]_error metric.
//
//nolint:goconst // improves readability
func (r *BeatRouteStats) sumErrorData(data metricdata.Aggregation) {
	switch t := data.(type) {
	case metricdata.Sum[int64]:
		for _, dp := range t.DataPoints {
			eType := ""
			for iter := dp.Attributes.Iter(); iter.Next(); {
				if iter.Attribute().Key == "error_type" {
					eType = iter.Attribute().Value.AsString()
					break
				}
			}

			switch eType {
			case "drop":
				r.Drop += dp.Value
			case "fail":
				r.Fail += dp.Value
			case "limit_max":
				r.LimitMax += dp.Value
			case "limit_rate":
				r.LimitRate += dp.Value
			case "not_found":
				r.NotFound += dp.Value
			case "throttle":
				r.Throttle += dp.Value
			default:
			}
		}
	case metricdata.Sum[float64]:
		for _, dp := range t.DataPoints {
			eType := ""
			for iter := dp.Attributes.Iter(); iter.Next(); {
				if iter.Attribute().Key == "error_type" {
					eType = iter.Attribute().Value.AsString()
					break
				}
			}

			switch eType {
			case "drop":
				r.Drop += int64(dp.Value)
			case "fail":
				r.Fail += int64(dp.Value)
			case "limit_max":
				r.LimitMax += int64(dp.Value)
			case "limit_rate":
				r.LimitRate += int64(dp.Value)
			case "not_found":
				r.NotFound += int64(dp.Value)
			case "throttle":
				r.Throttle += int64(dp.Value)
			default:
			}
		}
	default:
		// Gauges and Histogram are unsupported
	}
}

// beatExporter exposes otel metrics on an HTTP handler that metricbeat can consume
// It wraps the apmotel.Gatherer interface and otel.Reader's collect function in order to intercept and expose metrics data
type beatExporter struct {
	gatherer    apmotel.Gatherer
	httpEnabled bool

	l    sync.RWMutex
	ts   time.Time
	data BeatStats
}

// ServerHTTP is the handler to serve the /stats endpoint.
// If a non GET method is used a 405 status is returned.
// Otherwise  it will check if metrics have been updated within the last 10s, if not it will try to collect new metrics
// Metrics will be written as a JSON response body.
func (b *beatExporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	zlog := zerolog.Ctx(r.Context())
	b.l.RLock()
	if time.Since(b.ts) > time.Second*10 {
		b.l.RUnlock()
		rm := metricdata.ResourceMetrics{}
		if err := b.Collect(r.Context(), &rm); err != nil {
			zlog.Error().Err(err).Msg("Unable to collect resource metrics for export.")
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		b.l.RLock()
	}
	defer b.l.RUnlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(b.data); err != nil {
		zlog.Error().Err(err).Msg("/stats endpoint failed to write response.")
	}
}

// GatherMetrics is a wrapper for the APM MetricsGatherer that will also prepare data for exposure if the HTTP endpoint is running.
func (b *beatExporter) GatherMetrics(ctx context.Context, m *apm.Metrics) error {
	if err := b.gatherer.GatherMetrics(ctx, m); err != nil {
		return err
	}
	if !b.httpEnabled {
		return nil
	}

	rm := metricdata.ResourceMetrics{}
	if err := b.Collect(ctx, &rm); err != nil {
		zlog := zerolog.Ctx(ctx)
		zlog.Error().Err(err).Msg("Unable to collect resource metrics for export.")
	}
	return nil
}

// Collect is a wrapper for the otel.Reader's Collect method that will also expose ResourceMetrics as a JSON blob that Metricbeat can consume.
func (b *beatExporter) Collect(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if err := b.gatherer.Collect(ctx, rm); err != nil {
		return err
	}
	if !b.httpEnabled {
		return nil
	}
	b.l.Lock()
	defer b.l.Unlock()
	b.ts = time.Now().UTC()
	b.data = toBeatInfo(rm)
	return nil
}

// toBeatInfo converts ResourceMetrics to BeatStats
//
//nolint:goconst // having strings improves readability
func toBeatInfo(rm *metricdata.ResourceMetrics) BeatStats {
	bi := BeatStats{
		Beat: Beat{
			Info: BeatInfo{
				EphemeralID: eID,
				Uptime: struct {
					MS int64 `json:"ms"`
				}{
					MS: time.Since(initTS).Milliseconds(),
				},
			},
		},
	}
	if rm == nil {
		return bi
	}
	if rm.Resource != nil {
		for it := rm.Resource.Iter(); it.Next(); {
			kv := it.Attribute()
			switch kv.Key {
			case "service.name":
				bi.Beat.Info.Name = kv.Value.AsString()
			case "service.version":
				bi.Beat.Info.Version = kv.Value.AsString()
			default:
			}
		}
	}

	if len(rm.ScopeMetrics) < 1 {
		return bi
	}

	// Find the specific scope named fleet-server that will contain all API stats
	// Allow for len(rm.ScopeMetrics) > 1 in case some other part of fleet-server collects otel metrics from a different meter
	// for example with: otel.Meter("bulk-stats")
	scope := 0
	for i, s := range rm.ScopeMetrics {
		if s.Scope.Name == "fleet-server" {
			scope = i
			break
		}
	}

	for _, metric := range rm.ScopeMetrics[scope].Metrics {
		// map top level http stats
		switch metric.Name {
		case "tcp_open":
			bi.HTTPServer.TCPOpen = sumMetricData(metric.Data)
			continue
		case "tcp_close":
			bi.HTTPServer.TCPClose = sumMetricData(metric.Data)
			continue
		case "tcp_active":
			bi.HTTPServer.TCPActive = sumMetricData(metric.Data)
			continue
		default:
		}

		// map route-specific stats
		arrs := strings.SplitN(metric.Name, "_", 2)
		switch arrs[0] {
		case "checkin":
			bi.HTTPServer.Routes.Checkin.fromMetricData(arrs[1], metric.Data)
		case "enroll":
			bi.HTTPServer.Routes.Enroll.fromMetricData(arrs[1], metric.Data)
		case "acks":
			bi.HTTPServer.Routes.Acks.fromMetricData(arrs[1], metric.Data)
		case "status":
			bi.HTTPServer.Routes.Status.fromMetricData(arrs[1], metric.Data)
		case "uploadStart":
			bi.HTTPServer.Routes.UploadStart.fromMetricData(arrs[1], metric.Data)
		case "uploadChunk":
			bi.HTTPServer.Routes.UploadChunk.fromMetricData(arrs[1], metric.Data)
		case "uploadEnd":
			bi.HTTPServer.Routes.UploadEnd.fromMetricData(arrs[1], metric.Data)
		case "deliverFile":
			bi.HTTPServer.Routes.DeliverFile.fromMetricData(arrs[1], metric.Data)
		case "getPGPKey":
			bi.HTTPServer.Routes.GetPGPKey.fromMetricData(arrs[1], metric.Data)
		case "artifact":
			bi.HTTPServer.Routes.Artifacts.fromMetricData(arrs[1], metric.Data)
		default:
		}
	}

	return bi
}

// sumMetricData returns the sum of a metric's data values
// Currently it only supports the underlying Sum[int64|float64] type.
func sumMetricData(data metricdata.Aggregation) int64 {
	var i int64
	switch t := data.(type) {
	case metricdata.Sum[int64]:
		for _, dp := range t.DataPoints {
			i += dp.Value
		}
	case metricdata.Sum[float64]:
		for _, dp := range t.DataPoints {
			i += int64(dp.Value)
		}
	default:
		// Gauges and Histograms are unsupported
	}
	return i
}
