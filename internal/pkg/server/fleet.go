// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/go-ucfg"
	"go.elastic.co/apm/v2"
	apmtransport "go.elastic.co/apm/v2/transport"

	"github.com/elastic/fleet-server/v7/internal/pkg/action"
	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/coordinator"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/gc"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/profile"
	"github.com/elastic/fleet-server/v7/internal/pkg/scheduler"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
	"github.com/elastic/fleet-server/v7/internal/pkg/ver"

	"github.com/hashicorp/go-version"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

const kUAFleetServer = "Fleet-Server"

// Fleet is an instance of the fleet-server.
type Fleet struct {
	standAlone bool
	bi         build.Info
	verCon     version.Constraints

	cfgCh    chan *config.Config
	cache    cache.Cache
	reporter state.Reporter

	// Used for diagnostics reporting
	l   sync.RWMutex
	cfg *config.Config
}

// NewFleet creates the actual fleet server service.
func NewFleet(bi build.Info, reporter state.Reporter, standAlone bool) (*Fleet, error) {
	verCon, err := api.BuildVersionConstraint(bi.Version)
	if err != nil {
		return nil, err
	}

	return &Fleet{
		standAlone: standAlone,
		bi:         bi,
		verCon:     verCon,
		cfgCh:      make(chan *config.Config, 1),
		reporter:   reporter,
	}, nil
}

type runFunc func(context.Context) error

type runFuncCfg func(context.Context, *config.Config) error

func (f *Fleet) GetConfig() *config.Config {
	f.l.RLock()
	defer f.l.RUnlock()
	return f.cfg
}

// Run runs the fleet server
func (f *Fleet) Run(ctx context.Context, initCfg *config.Config) error {
	log := zerolog.Ctx(ctx)
	err := initCfg.LoadServerLimits()
	if err != nil {
		return fmt.Errorf("encountered error while loading server limits: %w", err)
	}
	cacheCfg := config.CopyCache(initCfg)
	log.Info().Interface("cfg", cacheCfg).Msg("Setting cache config options")
	cache, err := cache.New(cacheCfg)
	if err != nil {
		return err
	}
	f.cache = cache

	var curCfg *config.Config
	newCfg := initCfg

	// Replace context with cancellable ctx
	// in order to automatically cancel all the go routines
	// that were started in the scope of this function on function exit
	ctx, cn := context.WithCancel(ctx)
	defer cn()

	stop := func(cn context.CancelFunc, g *errgroup.Group) {
		if cn != nil {
			cn()
		}
		if g != nil {
			err := g.Wait()
			if err != nil {
				log.Error().Err(err).Msg("error encountered while stopping server")
			}
		}
	}

	start := func(ctx context.Context, runfn runFuncCfg, cfg *config.Config, ech chan<- error) (*errgroup.Group, context.CancelFunc) {
		ctx, cn = context.WithCancel(ctx)
		g, ctx := errgroup.WithContext(ctx)

		g.Go(func() error {
			err := runfn(ctx, cfg)
			if err != nil {
				ech <- err
			}
			return err
		})
		return g, cn
	}

	var (
		proCancel, srvCancel context.CancelFunc
		proEg, srvEg         *errgroup.Group
	)

	started := false
	ech := make(chan error, 2)

LOOP:
	for {
		if started {
			f.reporter.UpdateState(client.UnitStateConfiguring, "Re-configuring", nil) //nolint:errcheck // unclear on what should we do if updating the status fails?
		} else {
			started = true
			f.reporter.UpdateState(client.UnitStateStarting, "Starting", nil) //nolint:errcheck // unclear on what should we do if updating the status fails?
		}

		err := newCfg.LoadServerLimits()
		if err != nil {
			return fmt.Errorf("encountered error while loading server limits: %w", err)
		}

		// Create or recreate cache
		if configCacheChanged(curCfg, newCfg) {
			log.Info().Msg("reconfigure cache on configuration change")
			cacheCfg := config.CopyCache(newCfg)
			err := f.cache.Reconfigure(cacheCfg)
			log.Info().Err(err).Interface("cfg", cacheCfg).Msg("reconfigure cache complete")
			if err != nil {
				return err
			}
		}

		// Start or restart profiler
		if configChangedProfiler(curCfg, newCfg) {
			if proCancel != nil {
				log.Info().Msg("stopping profiler on configuration change")
				stop(proCancel, proEg)
			}
			proEg, proCancel = nil, nil
			if newCfg.Inputs[0].Server.Profiler.Enabled {
				log.Info().Msg("starting profiler on configuration change")
				proEg, proCancel = start(ctx, func(ctx context.Context, cfg *config.Config) error {
					return profile.RunProfiler(ctx, cfg.Inputs[0].Server.Profiler.Bind)
				}, newCfg, ech)
			}
		}

		// Start or restart server
		if configChangedServer(*log, curCfg, newCfg) {
			if srvCancel != nil {
				log.Info().Msg("stopping server on configuration change")
				stop(srvCancel, srvEg)
				select {
				case err := <-ech:
					log.Debug().Err(err).Msg("Server stopped intercepted expected context cancel error.")
				case <-time.After(time.Second * 5):
					log.Warn().Msg("Server stopped expected context cancel error missing.")
				}
			}
			log.Info().Msg("starting server on configuration change")
			srvEg, srvCancel = start(ctx, func(ctx context.Context, cfg *config.Config) error {
				return f.runServer(ctx, cfg)
			}, newCfg, ech)
		}

		curCfg = newCfg
		f.l.Lock()
		f.cfg = curCfg
		f.l.Unlock()

		select {
		case cfg := <-f.cfgCh:
			log.Info().Msg("Server configuration update")
			if cfg.Inputs == nil && cfg.RevisionIdx != 0 { // cfg only contains updated output retrieved from policy
				rev := cfg.RevisionIdx
				esOutput := config.MergeElasticsearchFromPolicy(curCfg.Output.Elasticsearch, cfg.Output.Elasticsearch)

				// test config
				cli, err := es.NewClient(ctx,
					&config.Config{
						Output: config.Output{
							Elasticsearch: esOutput,
						},
					},
					false,
					elasticsearchOptions(curCfg.Inputs[0].Server.Instrumentation.Enabled, f.bi)...,
				)
				if err != nil {
					log.Warn().Int64(logger.RevisionIdx, rev).Err(err).Msg("unable to create elasticsearch client from policy output")
					continue
				}
				remoteVersion, err := ver.CheckCompatibility(ctx, cli, f.bi.Version)
				if err != nil {
					// NOTE The error can indicate a bad network connection, bad TLS settings, etc.
					// But if the error is an ErrElasticVersionConflict then something is very wrong
					if errors.Is(err, es.ErrElasticVersionConflict) {
						log.Error().Err(err).Int64(logger.RevisionIdx, rev).Interface("output", esOutput).Interface("bootstrap", curCfg.Output.Elasticsearch).Str("remote_version", remoteVersion).Msg("Elasticsearch version constraint failed for new output")
					} else {
						log.Warn().Err(err).Int64(logger.RevisionIdx, rev).Msg("Failed version compatibility check using output from policy")
					}
					continue
				}
				// work around to get a new cfg object based off curCfg
				// we override the output with esOutput and have a complete config with a new mutex
				tmp, err := ucfg.NewFrom(curCfg, config.DefaultOptions...)
				if err != nil {
					log.Error().Err(err).Int64(logger.RevisionIdx, rev).Msg("Unable to convert config")
					continue
				}
				err = tmp.Unpack(cfg, config.DefaultOptions...)
				if err != nil {
					log.Error().Err(err).Int64(logger.RevisionIdx, rev).Msg("Unable to unpack config")
					continue
				}
				log.Info().Int64(logger.RevisionIdx, rev).Msg("Using output from policy")
				cfg.Output.Elasticsearch = esOutput
				cfg.RevisionIdx = rev
			}
			newCfg = cfg
		case err := <-ech:
			f.reporter.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error - %s", err), nil) //nolint:errcheck // unclear on what should we do if updating the status fails?
			log.Error().Err(err).Msg("Fleet Server failed")
			return err
		case <-ctx.Done():
			f.reporter.UpdateState(client.UnitStateStopping, "Stopping", nil) //nolint:errcheck // unclear on what should we do if updating the status fails?
			break LOOP
		}
	}

	// Server is coming down; wait for the server group to exit cleanly.
	// Timeout if something is locked up.
	err = safeWait(srvEg, curCfg.Inputs[0].Server.Timeouts.Drain)

	// Eat cancel error to minimize confusion in logs
	if errors.Is(err, context.Canceled) {
		err = nil
	}

	log.Info().Err(err).Msg("Fleet Server exited")
	return err
}

func configChangedProfiler(curCfg, newCfg *config.Config) bool {
	changed := true

	switch {
	case curCfg == nil:
	case curCfg.Inputs[0].Server.Profiler.Enabled != newCfg.Inputs[0].Server.Profiler.Enabled:
	case curCfg.Inputs[0].Server.Profiler.Bind != newCfg.Inputs[0].Server.Profiler.Bind:
	default:
		changed = false
	}

	return changed
}

func configCacheChanged(curCfg, newCfg *config.Config) bool {
	if curCfg == nil {
		return false
	}
	return curCfg.Inputs[0].Cache != newCfg.Inputs[0].Cache
}

func configChangedServer(log zerolog.Logger, curCfg, newCfg *config.Config) bool {
	zlog := log.With().Interface("new", newCfg.Redact()).Logger()

	changed := true
	switch {
	case curCfg == nil:
		zlog.Info().Msg("initial server configuration")
	case !reflect.DeepEqual(curCfg.Fleet.CopyNoLogging(), newCfg.Fleet.CopyNoLogging()):
		zlog.Info().
			Interface("old", curCfg.Redact()).
			Msg("fleet configuration has changed")
	case !reflect.DeepEqual(curCfg.Output, newCfg.Output):
		zlog.Info().
			Interface("old", curCfg.Redact()).
			Msg("output configuration has changed")
	case !reflect.DeepEqual(curCfg.Inputs[0].Server, newCfg.Inputs[0].Server):
		zlog.Info().
			Interface("old", curCfg.Redact()).
			Msg("server configuration has changed")
	default:
		changed = false
	}

	return changed
}

func safeWait(g *errgroup.Group, to time.Duration) error {
	var err error
	waitCh := make(chan error)
	go func() {
		waitCh <- g.Wait()
	}()

	select {
	case err = <-waitCh:
	case <-time.After(to):
		zerolog.Ctx(context.TODO()).Warn().Msg("deadlock: goroutine locked up on errgroup.Wait()")
		err = errors.New("group wait timeout")
	}

	return err
}

func loggedRunFunc(ctx context.Context, tag string, runfn runFunc) func() error {
	log := zerolog.Ctx(ctx)
	return func() error {
		log.Debug().Msg(tag + " started")

		err := runfn(ctx)

		lvl := zerolog.DebugLevel
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled):
			err = nil
		default:
			lvl = zerolog.ErrorLevel
		}

		log.WithLevel(lvl).Err(err).Msg(tag + " exited")
		return err
	}
}

func initRuntime(cfg *config.Config) {
	gcPercent := cfg.Inputs[0].Server.Runtime.GCPercent
	if gcPercent != 0 {
		old := debug.SetGCPercent(gcPercent)

		zerolog.Ctx(context.TODO()).Info().
			Int("old", old).
			Int("new", gcPercent).
			Msg("SetGCPercent")
	}
	memoryLimit := cfg.Inputs[0].Server.Runtime.MemoryLimit
	if memoryLimit != 0 {
		old := debug.SetMemoryLimit(memoryLimit)

		zerolog.Ctx(context.TODO()).Info().
			Int64("old", old).
			Int64("new", memoryLimit).
			Msg("SetMemoryLimit")
	}

}

func (f *Fleet) initBulker(ctx context.Context, tracer *apm.Tracer, cfg *config.Config) (*bulk.Bulker, error) {
	es, err := es.NewClient(ctx, cfg, false, elasticsearchOptions(
		cfg.Inputs[0].Server.Instrumentation.Enabled, f.bi,
	)...)
	if err != nil {
		return nil, err
	}

	bulkOpts := bulk.BulkOptsFromCfg(cfg)
	bulkOpts = append(bulkOpts, bulk.WithBi(f.bi))
	blk := bulk.NewBulker(es, tracer, bulkOpts...)
	return blk, nil
}

func (f *Fleet) runServer(ctx context.Context, cfg *config.Config) (err error) {
	initRuntime(cfg)

	// Create the APM tracer.
	tracer, err := f.initTracer(ctx, cfg.Inputs[0].Server.Instrumentation)
	if err != nil {
		return err
	}

	// The metricsServer is only enabled if http.enabled is set in the config
	metricsServer, err := api.InitMetrics(ctx, cfg, f.bi, tracer)
	switch {
	case err != nil:
		return err
	case metricsServer != nil:
		defer func() {
			_ = metricsServer.Stop()
		}()
	}

	// Bulker is started in its own context and managed in the scope of this function. This is done so
	// when the `ctx` is cancelled, the bulker will remain executing until this function exits.
	// This allows the child subsystems to continue to write to the data store while tearing down.
	bulkCtx, bulkCancel := context.WithCancel(context.Background())
	defer bulkCancel()

	// Create the bulker subsystem
	bulker, err := f.initBulker(bulkCtx, tracer, cfg)
	if err != nil {
		return err
	}

	// Execute the bulker engine in a goroutine with its orphaned context.
	// Create an error channel for the case where the bulker exits
	// unexpectedly (ie. not cancelled by the bulkCancel context).
	errCh := make(chan error)

	go func() {
		runFunc := loggedRunFunc(bulkCtx, "Bulker", bulker.Run)

		// Emit the error from bulker.Run to the local error channel.
		// The error group will be listening for it. (see comments below)
		errCh <- runFunc()
	}()

	// Wrap context with an error group context to manage the lifecycle
	// of the subsystems.  An error from any subsystem, or if the
	// parent context is cancelled, will cancel the group.
	// see https://pkg.go.dev/golang.org/x/sync/errgroup#Group.Go
	g, ctx := errgroup.WithContext(ctx)

	// Stub a function for inclusion in the errgroup that exits when
	// the bulker exits.  If the bulker exits before the error group,
	// this will tear down the error group and g.Wait() will return.
	// Otherwise it will be a noop.
	//nolint:nakedret // small function is easy to track
	g.Go(func() (err error) {
		select {
		case err = <-errCh:
		case <-ctx.Done():
			err = ctx.Err()
		}
		return
	})

	if tracer != nil {
		go func() {
			<-ctx.Done()
			zerolog.Ctx(ctx).Info().Msg("flushing instrumentation tracer...")
			tracer.Flush(nil)
			tracer.Close()
		}()
	}

	if err = f.runSubsystems(ctx, cfg, g, bulker, tracer); err != nil {
		return err
	}

	return g.Wait()
}

func (f *Fleet) runSubsystems(ctx context.Context, cfg *config.Config, g *errgroup.Group, bulker bulk.Bulk, tracer *apm.Tracer) (err error) {
	esCli := bulker.Client()

	// Version check is not performed in standalone mode because it is expected that
	// standalone Fleet Server may be running with older versions of Elasticsearch.
	if !f.standAlone {
		// Check version compatibility with Elasticsearch
		remoteVersion, err := ver.CheckCompatibility(ctx, esCli, f.bi.Version)
		if err != nil {
			if len(remoteVersion) != 0 {
				return fmt.Errorf("failed version compatibility check with elasticsearch (Agent: %s, Elasticsearch: %s): %w",
					f.bi.Version, remoteVersion, err)
			}
			return fmt.Errorf("failed version compatibility check with elasticsearch: %w", err)
		}
	}

	// Migrations are not executed in standalone mode. When needed, they will be executed
	// by some external process.
	if !f.standAlone {
		// Run migrations
		loggedMigration := loggedRunFunc(ctx, "Migrations", func(ctx context.Context) error {
			return dl.Migrate(ctx, bulker)
		})
		if err = loggedMigration(); err != nil {
			return fmt.Errorf("failed to run subsystems: %w", err)
		}
	}

	// Run scheduler for periodic GC/cleanup
	gcCfg := cfg.Inputs[0].Server.GC
	sched, err := scheduler.New(gc.Schedules(bulker, gcCfg.ScheduleInterval, gcCfg.CleanupAfterExpiredInterval))
	if err != nil {
		return fmt.Errorf("failed to create elasticsearch GC: %w", err)
	}
	g.Go(loggedRunFunc(ctx, "Elasticsearch GC", sched.Run))

	// Monitoring es client, longer timeout, no retries
	monCli, err := es.NewClient(ctx, cfg, true, elasticsearchOptions(
		cfg.Inputs[0].Server.Instrumentation.Enabled, f.bi,
	)...)
	if err != nil {
		return err
	}

	// Coordinator policy monitor
	pim, err := monitor.New(dl.FleetPolicies, esCli, monCli,
		monitor.WithFetchSize(cfg.Inputs[0].Monitor.FetchSize),
		monitor.WithPollTimeout(cfg.Inputs[0].Monitor.PollTimeout),
		monitor.WithAPMTracer(tracer),
		monitor.WithDebounceTime(cfg.Inputs[0].Monitor.PolicyDebounceTime),
	)
	if err != nil {
		return err
	}

	g.Go(loggedRunFunc(ctx, "Policy index monitor", pim.Run))
	cord := coordinator.NewMonitor(cfg.Fleet, f.bi.Version, bulker, pim, coordinator.NewCoordinatorZero)
	g.Go(loggedRunFunc(ctx, "Coordinator policy monitor", cord.Run))

	// Policy monitor
	pm := policy.NewMonitor(bulker, pim, cfg.Inputs[0].Server.Limits)
	g.Go(loggedRunFunc(ctx, "Policy monitor", pm.Run))

	// Policy self monitor
	var sm policy.SelfMonitor
	if f.standAlone {
		sm = policy.NewStandAloneSelfMonitor(bulker, f.reporter)
	} else {
		sm = policy.NewSelfMonitor(cfg.Fleet, bulker, pim, cfg.Inputs[0].Policy.ID, f.reporter, f.cfgCh)
	}
	g.Go(loggedRunFunc(ctx, "Policy self monitor", sm.Run))

	// Actions monitoring
	var am monitor.SimpleMonitor
	var ad *action.Dispatcher
	var tr *action.TokenResolver

	am, err = monitor.NewSimple(dl.FleetActions, esCli, monCli,
		monitor.WithExpiration(true),
		monitor.WithFetchSize(cfg.Inputs[0].Monitor.FetchSize),
		monitor.WithPollTimeout(cfg.Inputs[0].Monitor.PollTimeout),
		monitor.WithAPMTracer(tracer),
	)
	if err != nil {
		return err
	}
	g.Go(loggedRunFunc(ctx, "Action monitor", am.Run))

	ad = action.NewDispatcher(am, cfg.Inputs[0].Server.Limits.ActionLimit.Interval, cfg.Inputs[0].Server.Limits.ActionLimit.Burst)
	g.Go(loggedRunFunc(ctx, "Action dispatcher", ad.Run))
	tr, err = action.NewTokenResolver(bulker)
	if err != nil {
		return err
	}

	bc := checkin.NewBulk(bulker)
	g.Go(loggedRunFunc(ctx, "Bulk checkin", bc.Run))

	ct := api.NewCheckinT(f.verCon, &cfg.Inputs[0].Server, f.cache, bc, pm, am, ad, tr, bulker)
	et, err := api.NewEnrollerT(f.verCon, &cfg.Inputs[0].Server, bulker, f.cache)
	if err != nil {
		return err
	}

	at := api.NewArtifactT(&cfg.Inputs[0].Server, bulker, f.cache)
	ack := api.NewAckT(&cfg.Inputs[0].Server, bulker, f.cache)
	st := api.NewStatusT(&cfg.Inputs[0].Server, bulker, f.cache)
	ut := api.NewUploadT(&cfg.Inputs[0].Server, bulker, monCli, f.cache) // uses no-retry client for bufferless chunk upload
	ft := api.NewFileDeliveryT(&cfg.Inputs[0].Server, bulker, monCli, f.cache)
	pt := api.NewPGPRetrieverT(&cfg.Inputs[0].Server, bulker, f.cache)

	for _, endpoint := range (&cfg.Inputs[0].Server).BindEndpoints() {
		apiServer := api.NewServer(endpoint, &cfg.Inputs[0].Server, ct, et, at, ack, st, sm, f.bi, ut, ft, pt, bulker, tracer)
		g.Go(loggedRunFunc(ctx, "Http server", func(ctx context.Context) error {
			return apiServer.Run(ctx)
		}))
	}

	return err
}

// Reload reloads the fleet server with the latest configuration.
func (f *Fleet) Reload(ctx context.Context, cfg *config.Config) error {
	select {
	case f.cfgCh <- cfg:
	case <-ctx.Done():
	}
	return nil
}

const envAPMActive = "ELASTIC_APM_ACTIVE"

func (f *Fleet) initTracer(ctx context.Context, cfg config.Instrumentation) (*apm.Tracer, error) {
	if !cfg.Enabled && os.Getenv(envAPMActive) != "true" {
		return nil, nil
	}

	zerolog.Ctx(ctx).Info().Msg("fleet-server instrumentation is enabled")

	// Use env vars to configure additional APM settings.
	const (
		envGlobalLabels          = "ELASTIC_APM_GLOBAL_LABELS"
		envTransactionSampleRate = "ELASTIC_APM_TRANSACTION_SAMPLE_RATE"
	)
	if cfg.GlobalLabels != "" {
		os.Setenv(envGlobalLabels, cfg.GlobalLabels)
		defer os.Unsetenv(envGlobalLabels)
	}
	if cfg.TransactionSampleRate != "" {
		os.Setenv(envTransactionSampleRate, cfg.TransactionSampleRate)
		defer os.Unsetenv(envTransactionSampleRate)
	}

	options, err := cfg.APMHTTPTransportOptions()
	if err != nil {
		return nil, err
	}

	transport, err := apmtransport.NewHTTPTransport(options)
	if err != nil {
		return nil, err
	}

	return apm.NewTracerOptions(apm.TracerOptions{
		ServiceName:        "fleet-server",
		ServiceVersion:     f.bi.Version,
		ServiceEnvironment: cfg.Environment,
		Transport:          transport,
	})
}

func elasticsearchOptions(instumented bool, bi build.Info) []es.ConfigOption {
	options := []es.ConfigOption{es.WithUserAgent(kUAFleetServer, bi)}
	if instumented {
		options = append(options, es.InstrumentRoundTripper())
	}
	return options
}
