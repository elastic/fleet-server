// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/yaml"

	"github.com/elastic/fleet-server/v7/internal/pkg/action"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/coordinator"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/profile"
	"github.com/elastic/fleet-server/v7/internal/pkg/reload"
	"github.com/elastic/fleet-server/v7/internal/pkg/signal"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/status"
	"github.com/elastic/fleet-server/v7/internal/pkg/ver"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

const (
	kAgentMode                 = "agent-mode"
	kAgentModeRestartLoopDelay = 2 * time.Second
)

func installSignalHandler() context.Context {
	rootCtx := context.Background()
	return signal.HandleInterrupt(rootCtx)
}

func makeCache(cfg *config.Config) (cache.Cache, error) {
	cacheCfg := makeCacheConfig(cfg)
	log.Info().Interface("cfg", cacheCfg).Msg("makeCache")
	return cache.New(cacheCfg)
}

func makeCacheConfig(cfg *config.Config) cache.Config {
	ccfg := cfg.Inputs[0].Cache

	return cache.Config{
		NumCounters:  ccfg.NumCounters,
		MaxCost:      ccfg.MaxCost,
		ActionTTL:    ccfg.ActionTTL,
		EnrollKeyTTL: ccfg.EnrollKeyTTL,
		ArtifactTTL:  ccfg.ArtifactTTL,
		ApiKeyTTL:    ccfg.ApiKeyTTL,
		ApiKeyJitter: ccfg.ApiKeyJitter,
	}
}

func initLogger(cfg *config.Config, version, commit string) (*logger.Logger, error) {
	l, err := logger.Init(cfg)
	if err != nil {
		return nil, err
	}

	log.Info().
		Str("version", version).
		Str("commit", commit).
		Int("pid", os.Getpid()).
		Int("ppid", os.Getppid()).
		Str("exe", os.Args[0]).
		Strs("args", os.Args[1:]).
		Msg("boot")
	log.Debug().Strs("env", os.Environ()).Msg("environment")

	return l, err
}

func getRunCommand(version, commit string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		cfgObject := cmd.Flags().Lookup("E").Value.(*config.Flag)
		cliCfg := cfgObject.Config()

		agentMode, err := cmd.Flags().GetBool(kAgentMode)
		if err != nil {
			return err
		}

		var l *logger.Logger
		var runErr error
		if agentMode {
			cfg, err := config.FromConfig(cliCfg)
			if err != nil {
				return err
			}
			l, err = initLogger(cfg, version, commit)
			if err != nil {
				return err
			}

			agent, err := NewAgentMode(cliCfg, os.Stdin, version, l)
			if err != nil {
				return err
			}

			runErr = agent.Run(installSignalHandler())
		} else {
			cfgPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			cfgData, err := yaml.NewConfigWithFile(cfgPath, config.DefaultOptions...)
			if err != nil {
				return err
			}
			err = cfgData.Merge(cliCfg, config.DefaultOptions...)
			if err != nil {
				return err
			}
			cfg, err := config.FromConfig(cfgData)
			if err != nil {
				return err
			}

			l, err = initLogger(cfg, version, commit)
			if err != nil {
				return err
			}

			srv, err := NewFleetServer(cfg, version, status.NewLog())
			if err != nil {
				return err
			}

			runErr = srv.Run(installSignalHandler())
		}

		if runErr != nil && runErr != context.Canceled {
			log.Error().Err(runErr).Msg("Exiting")
			l.Sync()
			return runErr
		}
		l.Sync()
		return nil
	}
}

func NewCommand(version, commit string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet-server",
		Short: "Fleet Server controls a fleet of Elastic Agents",
		RunE:  getRunCommand(version, commit),
	}
	cmd.Flags().StringP("config", "c", "fleet-server.yml", "Configuration for Fleet Server")
	cmd.Flags().Bool(kAgentMode, false, "Running under execution of the Elastic Agent")
	cmd.Flags().VarP(config.NewFlag(), "E", "E", "Overwrite configuration value")
	return cmd
}

type firstCfg struct {
	cfg *config.Config
	err error
}

type AgentMode struct {
	cliCfg  *ucfg.Config
	version string

	reloadables []reload.Reloadable

	agent client.Client

	mux          sync.Mutex
	firstCfg     chan firstCfg
	srv          *FleetServer
	srvCtx       context.Context
	srvCanceller context.CancelFunc
	startChan    chan struct{}
}

func NewAgentMode(cliCfg *ucfg.Config, reader io.Reader, version string, reloadables ...reload.Reloadable) (*AgentMode, error) {
	var err error

	a := &AgentMode{
		cliCfg:      cliCfg,
		version:     version,
		reloadables: reloadables,
	}
	a.agent, err = client.NewFromReader(reader, a)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AgentMode) Run(ctx context.Context) error {
	ctx, canceller := context.WithCancel(ctx)
	defer canceller()

	a.firstCfg = make(chan firstCfg)
	a.startChan = make(chan struct{}, 1)
	log.Info().Msg("starting communication connection back to Elastic Agent")
	err := a.agent.Start(ctx)
	if err != nil {
		return err
	}

	// wait for the initial configuration to be sent from the
	// Elastic Agent before starting the actual Fleet Server.
	log.Info().Msg("waiting for Elastic Agent to send initial configuration")
	var cfg firstCfg
	select {
	case <-ctx.Done():
		return fmt.Errorf("never received initial configuration")
	case cfg = <-a.firstCfg:
	}

	// possible that first configuration resulted in an error
	if cfg.err != nil {
		// unblock startChan even though there was an error
		a.startChan <- struct{}{}
		return cfg.err
	}

	// start fleet server with the initial configuration and its
	// own context (needed so when OnStop occurs the fleet server
	// is stopped and not the elastic-agent-client as well)
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()
	log.Info().Msg("received initial configuration starting Fleet Server")
	srv, err := NewFleetServer(cfg.cfg, a.version, status.NewChained(status.NewLog(), a.agent))
	if err != nil {
		// unblock startChan even though there was an error
		a.startChan <- struct{}{}
		return err
	}
	a.mux.Lock()
	close(a.firstCfg)
	a.firstCfg = nil
	a.srv = srv
	a.srvCtx = srvCtx
	a.srvCanceller = srvCancel
	a.mux.Unlock()

	// trigger startChan so OnConfig can continue
	a.startChan <- struct{}{}

	// keep trying to restart the FleetServer on failure, reporting
	// the status back to Elastic Agent
	res := make(chan error)
	go func() {
		for {
			err := a.srv.Run(srvCtx)
			if err == nil || err == context.Canceled {
				res <- err
				return
			}
			// sleep some before calling Run again
			sleep.WithContext(srvCtx, kAgentModeRestartLoopDelay)
		}
	}()
	return <-res
}

func (a *AgentMode) OnConfig(s string) {
	a.mux.Lock()
	cliCfg := ucfg.MustNewFrom(a.cliCfg, config.DefaultOptions...)
	srv := a.srv
	ctx := a.srvCtx
	canceller := a.srvCanceller
	cfgChan := a.firstCfg
	startChan := a.startChan
	a.mux.Unlock()

	var cfg *config.Config
	var err error
	defer func() {
		if err != nil {
			if cfgChan != nil {
				// failure on first config
				cfgChan <- firstCfg{
					cfg: nil,
					err: err,
				}
				// block until startChan signalled
				<-startChan
				return
			}

			log.Err(err).Msg("failed to reload configuration")
			if canceller != nil {
				canceller()
			}
		}
	}()

	// load configuration and then merge it on top of the CLI configuration
	var cfgData *ucfg.Config
	cfgData, err = yaml.NewConfig([]byte(s), config.DefaultOptions...)
	if err != nil {
		return
	}
	err = cliCfg.Merge(cfgData, config.DefaultOptions...)
	if err != nil {
		return
	}
	cfg, err = config.FromConfig(cliCfg)
	if err != nil {
		return
	}

	if cfgChan != nil {
		// reload the generic reloadables
		for _, r := range a.reloadables {
			err = r.Reload(ctx, cfg)
			if err != nil {
				return
			}
		}

		// send starting configuration so Fleet Server can start
		cfgChan <- firstCfg{
			cfg: cfg,
			err: nil,
		}

		// block handling more OnConfig calls until the Fleet Server
		// has been fully started
		<-startChan
	} else if srv != nil {
		// reload the generic reloadables
		for _, r := range a.reloadables {
			err = r.Reload(ctx, cfg)
			if err != nil {
				return
			}
		}

		// reload the server
		err = srv.Reload(ctx, cfg)
		if err != nil {
			return
		}
	} else {
		err = fmt.Errorf("internal service should have been started")
		return
	}
}

func (a *AgentMode) OnStop() {
	a.mux.Lock()
	canceller := a.srvCanceller
	a.mux.Unlock()

	if canceller != nil {
		canceller()
	}
}

func (a *AgentMode) OnError(err error) {
	// Log communication error through the logger. These errors are only
	// provided for logging purposes. The elastic-agent-client handles
	// retries and reconnects internally automatically.
	log.Err(err)
}

type FleetServer struct {
	ver      string
	verCon   version.Constraints
	policyId string

	cfg      *config.Config
	cfgCh    chan *config.Config
	cache    cache.Cache
	reporter status.Reporter
}

// NewFleetServer creates the actual fleet server service.
func NewFleetServer(cfg *config.Config, verStr string, reporter status.Reporter) (*FleetServer, error) {
	verCon, err := buildVersionConstraint(verStr)
	if err != nil {
		return nil, err
	}

	cache, err := makeCache(cfg)
	if err != nil {
		return nil, err
	}

	return &FleetServer{
		ver:      verStr,
		verCon:   verCon,
		cfg:      cfg,
		cfgCh:    make(chan *config.Config, 1),
		cache:    cache,
		reporter: reporter,
	}, nil
}

type runFunc func(context.Context) error

// Run runs the fleet server.
func (f *FleetServer) Run(ctx context.Context) error {
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
			g.Wait()
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
			f.reporter.Status(proto.StateObserved_CONFIGURING, "Re-configuring", nil)
		} else {
			started = true
			f.reporter.Status(proto.StateObserved_STARTING, "Starting", nil)
		}

		// Create or recreate cache
		if configCacheChanged(curCfg, newCfg) {
			cacheCfg := makeCacheConfig(newCfg)
			err := f.cache.Reconfigure(cacheCfg)
			log.Info().Err(err).Interface("cfg", cacheCfg).Msg("Reconfigure cache")
			if err != nil {
				return err
			}
		}

		// Start or restart profiler
		if configChangedProfiler(curCfg, newCfg) {
			stop(proCancel, proEg)
			proEg, proCancel = nil, nil
			if newCfg.Inputs[0].Server.Profiler.Enabled {
				proEg, proCancel = start(ctx, func(ctx context.Context) error {
					return profile.RunProfiler(ctx, newCfg.Inputs[0].Server.Profiler.Bind)
				}, ech)
			}
		}

		// Start or restart server
		if configChangedServer(curCfg, newCfg) {
			stop(srvCancel, srvEg)
			srvEg, srvCancel = start(ctx, func(ctx context.Context) error {
				return f.runServer(ctx, newCfg)
			}, ech)
		}

		curCfg = newCfg

		select {
		case newCfg = <-f.cfgCh:
			log.Info().Msg("Server configuration update")
		case err := <-ech:
			f.reporter.Status(proto.StateObserved_FAILED, fmt.Sprintf("Error - %s", err), nil)
			log.Error().Err(err).Msg("Fleet Server failed")
			return err
		case <-ctx.Done():
			f.reporter.Status(proto.StateObserved_STOPPING, "Stopping", nil)
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

func configChangedServer(curCfg, newCfg *config.Config) bool {
	return curCfg == nil || curCfg.Inputs[0].Server != newCfg.Inputs[0].Server
}

func configCacheChanged(curCfg, newCfg *config.Config) bool {
	if curCfg == nil {
		return false
	}
	return curCfg.Inputs[0].Cache != newCfg.Inputs[0].Cache
}

func safeWait(g *errgroup.Group, to time.Duration) (err error) {
	waitCh := make(chan error)
	go func() {
		waitCh <- g.Wait()
	}()

	select {
	case err = <-waitCh:
	case <-time.After(to):
		log.Warn().Msg("deadlock: goroutine locked up on errgroup.Wait()")
		err = errors.New("Group wait timeout")
	}

	return
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

func initBulker(ctx context.Context, cfg *config.Config) (*bulk.Bulker, error) {
	es, err := es.NewClient(ctx, cfg, false)
	if err != nil {
		return nil, err
	}

	blk := bulk.NewBulker(es, bulk.BulkOptsFromCfg(cfg)...)
	return blk, nil
}

func (f *FleetServer) runServer(ctx context.Context, cfg *config.Config) (err error) {
	initRuntime(cfg)

	// The metricsServer is only enabled if http.enabled is set in the config
	metricsServer, err := f.initMetrics(ctx, cfg)
	switch {
	case err != nil:
		return err
	case metricsServer != nil:
		defer metricsServer.Stop()
	}

	// Bulker is started in its own context and managed in the scope of this function. This is done so
	// when the `ctx` is cancelled, the bulker will remain executing until this function exits.
	// This allows the child subsystems to continue to write to the data store while tearing down.
	bulkCtx, bulkCancel := context.WithCancel(context.Background())
	defer bulkCancel()

	// Create the bulker subsystem
	bulker, err := initBulker(bulkCtx, cfg)
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

	if err = f.runSubsystems(ctx, cfg, g, bulker); err != nil {
		return err
	}

	return g.Wait()
}

func (f *FleetServer) runSubsystems(ctx context.Context, cfg *config.Config, g *errgroup.Group, bulker bulk.Bulk) (err error) {
	esCli := bulker.Client()

	// Check version compatibility with Elasticsearch
	err = ver.CheckCompatibility(ctx, esCli, f.ver)
	if err != nil {
		return fmt.Errorf("failed version compatibility check with elasticsearch: %w", err)
	}

	// Monitoring es client, longer timeout, no retries
	monCli, err := es.NewClient(ctx, cfg, true)
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
	cord := coordinator.NewMonitor(cfg.Fleet, f.ver, bulker, pim, coordinator.NewCoordinatorZero)
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

	ct := NewCheckinT(f.verCon, &cfg.Inputs[0].Server, f.cache, bc, pm, am, ad, tr, bulker)
	et, err := NewEnrollerT(f.verCon, &cfg.Inputs[0].Server, bulker, f.cache)
	if err != nil {
		return err
	}

	at := NewArtifactT(&cfg.Inputs[0].Server, bulker, f.cache)
	ack := NewAckT(&cfg.Inputs[0].Server, bulker, f.cache)

	router := NewRouter(bulker, ct, et, at, ack, sm)

	g.Go(loggedRunFunc(ctx, "Http server", func(ctx context.Context) error {
		return runServer(ctx, router, &cfg.Inputs[0].Server)
	}))

	return err
}

// Reload reloads the fleet server with the latest configuration.
func (f *FleetServer) Reload(ctx context.Context, cfg *config.Config) error {
	select {
	case f.cfgCh <- cfg:
	case <-ctx.Done():
	}
	return nil
}
