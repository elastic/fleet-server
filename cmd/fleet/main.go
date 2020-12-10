// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"sync"
	"time"

	"fleet/internal/pkg/action"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/env"
	"fleet/internal/pkg/esboot"
	"fleet/internal/pkg/logger"
	"fleet/internal/pkg/migrate"
	"fleet/internal/pkg/monitor"
	"fleet/internal/pkg/profile"
	"fleet/internal/pkg/runner"
	"fleet/internal/pkg/saved"
	"fleet/internal/pkg/signal"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const kPolicyThrottle = time.Millisecond * 5

var Version string

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
		err = initGlobalCache()
		checkErr(err)

		srv, err := NewFleetServer(cfg)
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
	cfg   *config.Config
	cfgCh chan *config.Config
}

// NewFleetServer creates the actual fleet server service.
func NewFleetServer(cfg *config.Config) (*FleetServer, error) {
	return &FleetServer{
		cfg:   cfg,
		cfgCh: make(chan *config.Config, 1),
	}, nil
}

// Run runs the fleet server.
func (f *FleetServer) Run(ctx context.Context) error {
	var curCfg *config.Config
	newCfg := f.cfg

	// To avoid repeating the same code for policy server and http server
	// The original code required them to be restarted independently,
	// to avoid restarting HTTP server when the profiler is enabled/disabled
	start := func(cn context.CancelFunc,
		wg *sync.WaitGroup,
		runfn runner.RunFunc,
		errCh chan<- error,
	) context.CancelFunc {
		if cn != nil {
			cn()
		}
		wg.Wait()
		cx, cn := context.WithCancel(ctx)
		runner.Start(cx, wg, runfn, func(er error) {
			if er != nil {
				errCh <- er
			}
		})
		return cn
	}

	var (
		proCancel, srvCancel context.CancelFunc
		proWg, srvWg         sync.WaitGroup
	)

	for {
		ech := make(chan error, 2)

		if curCfg == nil || curCfg.Inputs[0].Server.Profile.Bind != newCfg.Inputs[0].Server.Profile.Bind {
			proCancel = start(proCancel, &proWg, func(ctx context.Context) error {
				return profile.RunProfiler(ctx, newCfg.Inputs[0].Server.Profile.Bind)
			}, ech)
		}

		if curCfg == nil || curCfg.Inputs[0].Server != newCfg.Inputs[0].Server {
			srvCancel = start(srvCancel, &srvWg, func(ctx context.Context) error {
				return f.runServer(ctx, newCfg)
			}, ech)
		}

		curCfg = newCfg

		// Listen for errors or context cancel
		select {
		case newCfg = <-f.cfgCh:
			log.Debug().Msg("Server configuration update")
		case err := <-ech:
			log.Error().Err(err).Msg("Fleet Server failed")
		case <-ctx.Done():
			log.Info().Msg("Fleet Server exited")
			return nil
		}
	}
}

func (f *FleetServer) runServer(ctx context.Context, cfg *config.Config) (err error) {
	es, bulker, err := bulk.InitES(ctx, cfg)
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

	var funcs []runner.RunFunc
	var wg sync.WaitGroup

	// Policy monitor
	pm, err := NewPolicyMon(kPolicyThrottle)
	funcs = append(funcs, runner.LoggedRunFunc("Policy monitor", func(ctx context.Context) error {
		return pm.Monitor(ctx, sv)
	}))

	// Actions monitoring
	var am *monitor.Monitor
	var ad *action.Dispatcher
	var tr *action.TokenResolver

	// Behind the feature flag
	if f.cfg.Features.Enabled(config.FeatureActions) {
		am, err = monitor.New(dl.FleetActions, es, monitor.WithExpiration(true))
		if err != nil {
			return err
		}
		funcs = append(funcs, runner.LoggedRunFunc("Action monitor", am.Run))

		ad = action.NewDispatcher(am)
		funcs = append(funcs, runner.LoggedRunFunc("Action dispatcher", ad.Run))
		tr, err = action.NewTokenResolver(bulker)
		if err != nil {
			return err
		}
	}

	ba := NewBulkActions()
	funcs = append(funcs, runner.LoggedRunFunc("Bulk action", func(ctx context.Context) error {
		return ba.Run(ctx, sv)
	}))

	bc := NewBulkCheckin(bulker)
	funcs = append(funcs, runner.LoggedRunFunc("Bulk checkin", func(ctx context.Context) error {
		return bc.Run(ctx, sv)
	}))

	ct := NewCheckinT(f.cfg, bc, ba, pm, am, ad, tr, bulker)
	et, err := NewEnrollerT(&f.cfg.Inputs[0].Server, bulker)
	if err != nil {
		return err
	}
	router := NewRouter(sv, bulker, ct, et)

	funcs = append(funcs, runner.LoggedRunFunc("Http server", func(ctx context.Context) error {
		return runServer(ctx, router, &f.cfg.Inputs[0].Server)
	}))

	runner.StartGroup(ctx, &wg, funcs,
		func(er error) {
			if err == nil {
				err = er
			}
		},
	)

	wg.Wait()

	return nil
}

// Reload reloads the fleet server with the latest configuration.
func (f *FleetServer) Reload(ctx context.Context, cfg *config.Config) error {
	select {
	case f.cfgCh <- cfg:
	case <-ctx.Done():
	}
	return nil
}
