// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
	"net/url"
	"os"
	"reflect"
	"runtime/debug"
	"time"

	"go.elastic.co/apm"
	apmtransport "go.elastic.co/apm/transport"

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
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/profile"
	"github.com/elastic/fleet-server/v7/internal/pkg/scheduler"
	"github.com/elastic/fleet-server/v7/internal/pkg/ver"

	"github.com/hashicorp/go-version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

const kUAFleetServer = "Fleet-Server"

// Fleet is an instance of the fleet-server.
type Fleet struct {
	bi     build.Info
	verCon version.Constraints

	cfg      *config.Config
	cfgCh    chan *config.Config
	cache    cache.Cache
	reporter state.Reporter
}

// NewFleet creates the actual fleet server service.
func NewFleet(cfg *config.Config, bi build.Info, reporter state.Reporter) (*Fleet, error) {
	verCon, err := api.BuildVersionConstraint(bi.Version)
	if err != nil {
		return nil, err
	}

	err = cfg.LoadServerLimits()
	if err != nil {
		return nil, fmt.Errorf("encountered error while loading server limits: %w", err)
	}

	cacheCfg := config.CopyCache(cfg)
	log.Info().Interface("cfg", cacheCfg).Msg("Setting cache config options")
	cache, err := cache.New(cacheCfg)
	if err != nil {
		return nil, err
	}

	return &Fleet{
		bi:       bi,
		verCon:   verCon,
		cfg:      cfg,
		cfgCh:    make(chan *config.Config, 1),
		cache:    cache,
		reporter: reporter,
	}, nil
}

type runFunc func(context.Context) error

// Run runs the fleet server
func (f *Fleet) Run(ctx context.Context) error {
	var curCfg *config.Config
	newCfg := f.cfg

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

	start := func(ctx context.Context, runfn runFunc, ech chan<- error) (*errgroup.Group, context.CancelFunc) {
		ctx, cn = context.WithCancel(ctx)
		g, ctx := errgroup.WithContext(ctx)

		g.Go(func() error {
			err := runfn(ctx)
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

LOOP:
	for {
		ech := make(chan error, 2)
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
				proEg, proCancel = start(ctx, func(ctx context.Context) error {
					return profile.RunProfiler(ctx, newCfg.Inputs[0].Server.Profiler.Bind)
				}, ech)
			}
		}

		// Start or restart server
		if configChangedServer(curCfg, newCfg) {
			if srvCancel != nil {
				log.Info().Msg("stopping server on configuration change")
				stop(srvCancel, srvEg)
			}
			log.Info().Msg("starting server on configuration change")
			srvEg, srvCancel = start(ctx, func(ctx context.Context) error {
				return f.runServer(ctx, newCfg)
			}, ech)
		}

		curCfg = newCfg
		f.cfg = curCfg

		select {
		case newCfg = <-f.cfgCh:
			log.Info().Msg("Server configuration update")
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
	err := safeWait(srvEg, time.Second)

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

func configChangedServer(curCfg, newCfg *config.Config) bool {
	zlog := log.With().Interface("new", newCfg.Redact()).Logger()

	changed := true
	switch {
	case curCfg == nil:
		zlog.Info().Msg("initial server configuration")
	case !reflect.DeepEqual(curCfg.Fleet, newCfg.Fleet):
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
		log.Warn().Msg("deadlock: goroutine locked up on errgroup.Wait()")
		err = errors.New("group wait timeout")
	}

	return err
}

func loggedRunFunc(ctx context.Context, tag string, runfn runFunc) func() error {
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

		log.Info().
			Int("old", old).
			Int("new", gcPercent).
			Msg("SetGCPercent")
	}
}

func (f *Fleet) initBulker(ctx context.Context, tracer *apm.Tracer, cfg *config.Config) (*bulk.Bulker, error) {
	es, err := es.NewClient(ctx, cfg, false, elasticsearchOptions(
		cfg.Inputs[0].Server.Instrumentation.Enabled, f.bi,
	)...)
	if err != nil {
		return nil, err
	}

	blk := bulk.NewBulker(es, tracer, bulk.BulkOptsFromCfg(cfg)...)
	return blk, nil
}

func (f *Fleet) runServer(ctx context.Context, cfg *config.Config) (err error) {
	initRuntime(cfg)

	// The metricsServer is only enabled if http.enabled is set in the config
	metricsServer, err := api.InitMetrics(ctx, cfg, f.bi)
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

	// Create the APM tracer.
	tracer, err := f.initTracer(cfg.Inputs[0].Server.Instrumentation)
	if err != nil {
		return err
	}

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
			log.Info().Msg("flushing instrumentation tracer...")
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

	// Check version compatibility with Elasticsearch
	remoteVersion, err := ver.CheckCompatibility(ctx, esCli, f.bi.Version)
	if err != nil {
		if len(remoteVersion) != 0 {
			return fmt.Errorf("failed version compatibility check with elasticsearch (Agent: %s, Elasticsearch: %s): %w",
				f.bi.Version, remoteVersion, err)
		}
		return fmt.Errorf("failed version compatibility check with elasticsearch: %w", err)
	}

	// Run migrations
	loggedMigration := loggedRunFunc(ctx, "Migrations", func(ctx context.Context) error {
		return dl.Migrate(ctx, bulker)
	})
	if err = loggedMigration(); err != nil {
		return fmt.Errorf("failed to run subsystems: %w", err)
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
	)
	if err != nil {
		return err
	}

	g.Go(loggedRunFunc(ctx, "Policy index monitor", pim.Run))
	cord := coordinator.NewMonitor(cfg.Fleet, f.bi.Version, bulker, pim, coordinator.NewCoordinatorZero)
	g.Go(loggedRunFunc(ctx, "Coordinator policy monitor", cord.Run))

	// Policy monitor
	pm := policy.NewMonitor(bulker, pim, cfg.Inputs[0].Server.Limits.PolicyThrottle)
	g.Go(loggedRunFunc(ctx, "Policy monitor", pm.Run))

	// Policy self monitor
	sm := policy.NewSelfMonitor(cfg.Fleet, bulker, pim, cfg.Inputs[0].Policy.ID, f.reporter)
	g.Go(loggedRunFunc(ctx, "Policy self monitor", sm.Run))

	// Actions monitoring
	var am monitor.SimpleMonitor
	var ad *action.Dispatcher
	var tr *action.TokenResolver

	am, err = monitor.NewSimple(dl.FleetActions, esCli, monCli,
		monitor.WithExpiration(true),
		monitor.WithFetchSize(cfg.Inputs[0].Monitor.FetchSize),
		monitor.WithPollTimeout(cfg.Inputs[0].Monitor.PollTimeout),
	)
	if err != nil {
		return err
	}
	g.Go(loggedRunFunc(ctx, "Revision monitor", am.Run))

	ad = action.NewDispatcher(am)
	g.Go(loggedRunFunc(ctx, "Revision dispatcher", ad.Run))
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

	router := api.NewRouter(&cfg.Inputs[0].Server, bulker, ct, et, at, ack, st, sm, tracer, f.bi)

	g.Go(loggedRunFunc(ctx, "Http server", func(ctx context.Context) error {
		return router.Run(ctx)
	}))

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

func (f *Fleet) initTracer(cfg config.Instrumentation) (*apm.Tracer, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	log.Info().Msg("fleet-server instrumentation is enabled")

	// TODO(marclop): Ideally, we'd use apmtransport.NewHTTPTransportOptions()
	// but it doesn't exist today. Update this code once we have something
	// available via the APM Go agent.
	const (
		envVerifyServerCert      = "ELASTIC_APM_VERIFY_SERVER_CERT"
		envServerCert            = "ELASTIC_APM_SERVER_CERT"
		envCACert                = "ELASTIC_APM_SERVER_CA_CERT_FILE"
		envGlobalLabels          = "ELASTIC_APM_GLOBAL_LABELS"
		envTransactionSampleRate = "ELASTIC_APM_TRANSACTION_SAMPLE_RATE"
	)
	if cfg.TLS.SkipVerify {
		os.Setenv(envVerifyServerCert, "false")
		defer os.Unsetenv(envVerifyServerCert)
	}
	if cfg.TLS.ServerCertificate != "" {
		os.Setenv(envServerCert, cfg.TLS.ServerCertificate)
		defer os.Unsetenv(envServerCert)
	}
	if cfg.TLS.ServerCA != "" {
		os.Setenv(envCACert, cfg.TLS.ServerCA)
		defer os.Unsetenv(envCACert)
	}
	if cfg.GlobalLabels != "" {
		os.Setenv(envGlobalLabels, cfg.GlobalLabels)
		defer os.Unsetenv(envGlobalLabels)
	}
	if cfg.TransactionSampleRate != "" {
		os.Setenv(envTransactionSampleRate, cfg.TransactionSampleRate)
		defer os.Unsetenv(envTransactionSampleRate)
	}
	transport, err := apmtransport.NewHTTPTransport()
	if err != nil {
		return nil, err
	}

	if len(cfg.Hosts) > 0 {
		hosts := make([]*url.URL, 0, len(cfg.Hosts))
		for _, host := range cfg.Hosts {
			u, err := url.Parse(host)
			if err != nil {
				return nil, fmt.Errorf("failed parsing %s: %w", host, err)
			}
			hosts = append(hosts, u)
		}
		transport.SetServerURL(hosts...)
	}
	if cfg.APIKey != "" {
		transport.SetAPIKey(cfg.APIKey)
	} else {
		transport.SetSecretToken(cfg.SecretToken)
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
