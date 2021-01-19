// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/action"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/coordinator"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/env"
	"github.com/elastic/fleet-server/v7/internal/pkg/esboot"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/migrate"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/profile"
	"github.com/elastic/fleet-server/v7/internal/pkg/saved"
	"github.com/elastic/fleet-server/v7/internal/pkg/signal"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

const kPolicyThrottle = time.Millisecond * 5

func checkErr(err error) {
	if err != nil && err != context.Canceled {
		panic(err)
	}
}

func savedObjectKey() string {
	key := env.GetStr(
		"ES_SAVED_KEY",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	log.Debug().Str("key", key).Msg("saved objects")
	return key
}

func installSignalHandler() context.Context {
	rootCtx := context.Background()
	return signal.HandleInterrupt(rootCtx)
}

func getRunCommand(version string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {

		cfgPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return err
		}
		cfg, err := config.LoadFile(cfgPath)
		if err != nil {
			return err
		}

		logger.Init(cfg)

		ctx := installSignalHandler()
		c, err := cache.New()
		checkErr(err)

		srv, err := NewFleetServer(cfg, c, version)
		checkErr(err)

		return srv.Run(ctx)
	}
}

func NewCommand(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet-server",
		Short: "Fleet Server controls a fleet of Elastic Agents",
		RunE:  getRunCommand(version),
	}
	cmd.Flags().StringP("config", "c", "fleet-server.yml", "Configuration for Fleet Server")
	return cmd
}

type FleetServer struct {
	version string

	cfg   *config.Config
	cfgCh chan *config.Config
	cache cache.Cache
}

// NewFleetServer creates the actual fleet server service.
func NewFleetServer(cfg *config.Config, c cache.Cache, version string) (*FleetServer, error) {
	return &FleetServer{
		version: version,
		cfg:     cfg,
		cfgCh:   make(chan *config.Config, 1),
		cache:   c,
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

	for {
		ech := make(chan error, 2)

		// Restart profiler
		if curCfg == nil || curCfg.Inputs[0].Server.Profile.Bind != newCfg.Inputs[0].Server.Profile.Bind {
			stop(proCancel, proEg)
			proEg, proCancel = start(ctx, func(ctx context.Context) error {
				return profile.RunProfiler(ctx, newCfg.Inputs[0].Server.Profile.Bind)
			}, ech)
		}

		// Restart server
		if curCfg == nil || curCfg.Inputs[0].Server != newCfg.Inputs[0].Server {
			stop(srvCancel, srvEg)
			srvEg, srvCancel = start(ctx, func(ctx context.Context) error {
				return f.runServer(ctx, newCfg)
			}, ech)
		}

		curCfg = newCfg

		select {
		case newCfg = <-f.cfgCh:
			log.Debug().Msg("Server configuration update")
		case err := <-ech:
			log.Error().Err(err).Msg("Fleet Server failed")
			return nil
		case <-ctx.Done():
			log.Info().Msg("Fleet Server exited")
			return nil
		}
	}
}

func loggedRunFunc(ctx context.Context, tag string, runfn runFunc) func() error {
	return func() error {
		log.Debug().Msg(tag + " started")
		err := runfn(ctx)
		var ev *zerolog.Event
		if err != nil {
			log.Error().Err(err)
		}
		ev = log.Debug()
		ev.Msg(tag + " exited")
		return err
	}
}

func (f *FleetServer) runServer(ctx context.Context, cfg *config.Config) (err error) {
	// Bulker is started in its own context and managed inside of this function. This is done so
	// when the `ctx` is cancelled every worker using the bulker can get everything written on
	// shutdown before the bulker is then cancelled.
	bulkCtx, bulkCancel := context.WithCancel(context.Background())
	defer bulkCancel()
	es, bulker, err := bulk.InitES(bulkCtx, cfg)
	if err != nil {
		return err
	}
	sv := saved.NewMgr(bulker, savedObjectKey())

	// Initial indices bootstrapping, needed for agents actions development
	// TODO: remove this after the indices bootstrapping logic implemented in ES plugin
	err = esboot.EnsureESIndices(ctx, es)
	if err != nil {
		return err
	}
	err = migrate.Migrate(ctx, sv, bulker)
	if err != nil {
		return err
	}

	// Replacing to errgroup context
	g, ctx := errgroup.WithContext(ctx)

	// Coordinator policy monitor
	pim, err := monitor.New(dl.FleetPolicies, es)
	if err != nil {
		return err
	}

	g.Go(loggedRunFunc(ctx, "Policy index monitor", pim.Run))
	cord := coordinator.NewMonitor(cfg.Fleet, f.version, bulker, pim, coordinator.NewCoordinatorZero)
	g.Go(loggedRunFunc(ctx, "Coordinator policy monitor", cord.Run))

	// Policy monitor
	pm := policy.NewMonitor(bulker, pim, kPolicyThrottle)
	g.Go(loggedRunFunc(ctx, "Policy monitor", pm.Run))

	// Actions monitoring
	var am monitor.SimpleMonitor
	var ad *action.Dispatcher
	var tr *action.TokenResolver

	// Behind the feature flag
	am, err = monitor.NewSimple(dl.FleetActions, es, monitor.WithExpiration(true))
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

	bc := NewBulkCheckin(bulker)
	g.Go(loggedRunFunc(ctx, "Bulk checkin", func(ctx context.Context) error {
		return bc.Run(ctx, sv)
	}))

	ct := NewCheckinT(f.cfg, f.cache, bc, pm, am, ad, tr, bulker)
	et, err := NewEnrollerT(&f.cfg.Inputs[0].Server, bulker, f.cache)
	if err != nil {
		return err
	}
	router := NewRouter(bulker, ct, et)

	g.Go(loggedRunFunc(ctx, "Http server", func(ctx context.Context) error {
		return runServer(ctx, router, &f.cfg.Inputs[0].Server)
	}))

	return g.Wait()
}

// Reload reloads the fleet server with the latest configuration.
func (f *FleetServer) Reload(ctx context.Context, cfg *config.Config) error {
	select {
	case f.cfgCh <- cfg:
	case <-ctx.Done():
	}
	return nil
}
