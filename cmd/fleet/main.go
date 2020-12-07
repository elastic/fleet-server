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
	"fleet/internal/pkg/env"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/esboot"
	"fleet/internal/pkg/logger"
	"fleet/internal/pkg/profile"
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

func runBulkCheckin(ctx context.Context, bulker bulk.Bulk, sv saved.CRUD) *BulkCheckin {

	bc := NewBulkCheckin(bulker)
	go func() {
		for {
			err := bc.Run(ctx, sv)
			if err == context.Canceled {
				break
			}
			log.Error().Err(err).Msg("Restart bulk checkin on error")
		}
	}()
	return bc
}

func runBulkActions(ctx context.Context, sv saved.CRUD) *BulkActions {

	ba := NewBulkActions()
	go func() {
		for {
			err := ba.Run(ctx, sv)
			if err == context.Canceled {
				break
			}
			log.Error().Err(err).Msg("Restart bulk actions on error")
		}
	}()

	return ba
}

func runPolicyMon(ctx context.Context, sv saved.CRUD) (*PolicyMon, error) {
	pm, err := NewPolicyMon(kPolicyThrottle)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			err := pm.Monitor(ctx, sv)
			if err == context.Canceled {
				break
			}
			log.Error().Err(err).Msg("Restart policy monitor on error")
		}
	}()
	return pm, err
}

func runActionMon(ctx context.Context, bulker bulk.Bulk) (*action.Monitor, error) {
	am, err := action.NewMonitor(bulker)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			err := am.Run(ctx)
			if err == context.Canceled {
				break
			}
			log.Error().Err(err).Msg("Restart action monitor on error")
		}
	}()
	return am, nil
}

func runActionDispatcher(ctx context.Context, am *action.Monitor) *action.Dispatcher {
	ad := action.NewDispatcher(am)
	go func() {
		for {
			err := ad.Run(ctx)
			if err == context.Canceled {
				break
			}
			log.Error().Err(err).Msg("Restart action dispatcher on error")
		}
	}()
	return ad
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

		srv, err := NewFleetServer(ctx, cfg)
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

type fleetServer struct {
	cfg *config.Config

	es *es.Client
	sv saved.CRUD

	lock           sync.Mutex
	profilerCancel context.CancelFunc
	serverCancel   context.CancelFunc
	errCh          chan error
}

// NewFleetServer creates the actual fleet server service.
func NewFleetServer(ctx context.Context, cfg *config.Config) (*fleetServer, error) {
	es, err := es.New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sv := saved.NewMgr(es.Bulk(), savedObjectKey())
	return &fleetServer{
		cfg: cfg,
		es:  es,
		sv:  sv,
	}, nil
}

// Run runs the fleet server.
func (f *fleetServer) Run(ctx context.Context) error {
	// Initial indices bootstrapping, needed for agents actions development
	// TODO: remove this after the indices bootstrapping logic implemented in ES plugin
	err := esboot.EnsureESIndices(ctx, f.es)
	if err != nil {
		return err
	}

	// profiler restarts on reload
	profilerCtx, profilerCancel := context.WithCancel(ctx)
	err = profile.RunProfiler(profilerCtx, f.cfg.Inputs[0].Server.Profile.Bind)
	if err != nil {
		profilerCancel()
		return err
	}

	// server restarts on reload
	errCh := make(chan error)
	serverCancel, err := f.runServer(ctx, errCh)
	if err != nil {
		profilerCancel()
		serverCancel()
		return err
	}
	f.lock.Lock()
	f.profilerCancel = profilerCancel
	f.serverCancel = serverCancel
	f.errCh = errCh
	f.lock.Unlock()

	// block until error or main context is closed
	select {
	case err := <-errCh:
		log.Error().Err(err).Str("bind", f.cfg.Inputs[0].Server.BindAddress()).Msg("Fleet Server failed")
		return err
	case <-ctx.Done():
		log.Info().Err(err).Msg("Fleet Server exited")
		return nil
	}
}

func (f *fleetServer) runServer(ctx context.Context, errCh chan<- error) (context.CancelFunc, error) {
	serverCtx, serverCancel := context.WithCancel(ctx)
	pm, err := runPolicyMon(serverCtx, f.sv)
	if err != nil {
		serverCancel()
		return nil, err
	}

	// Start new actions monitoring
	var am *action.Monitor
	var ad *action.Dispatcher
	var tr *action.TokenResolver

	// Behind the feature flag
	if f.cfg.Features.Enabled(config.FeatureActions) {
		am, err = runActionMon(ctx, f.es.Bulk())
		if err != nil {
			serverCancel()
			return nil, err
		}
		ad = runActionDispatcher(ctx, am)
		tr, err = action.NewTokenResolver(f.es.Bulk())
		if err != nil {
			serverCancel()
			return nil, err
		}
	}

	ba := runBulkActions(serverCtx, f.sv)
	bc := runBulkCheckin(serverCtx, f.es.Bulk(), f.sv)
	ct := NewCheckinT(f.cfg, bc, ba, pm, am, ad, tr, f.es.Bulk())
	et := NewEnrollerT(&f.cfg.Inputs[0].Server, f.es.Bulk())
	router := NewRouter(f.sv, ct, et)

	err = runServer(serverCtx, router, &f.cfg.Inputs[0].Server, errCh)
	if err != nil {
		serverCancel()
		return nil, err
	}
	return serverCancel, nil
}

// Reload reloads the fleet server with the latest configuration.
func (f *fleetServer) Reload(ctx context.Context, cfg *config.Config) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	if err := f.es.Reload(ctx, cfg); err != nil {
		return err
	}
	if f.cfg.Inputs[0].Server.Profile.Bind != cfg.Inputs[0].Server.Profile.Bind {
		f.profilerCancel()
		profilerCtx, profilerCancel := context.WithCancel(ctx)
		err := profile.RunProfiler(profilerCtx, cfg.Inputs[0].Server.Profile.Bind)
		if err != nil {
			profilerCancel()
			return err
		}
		f.profilerCancel = profilerCancel
	}
	if f.cfg.Inputs[0].Server != cfg.Inputs[0].Server {
		f.serverCancel()
		serverCancel, err := f.runServer(ctx, f.errCh)
		if err != nil {
			return err
		}
		f.serverCancel = serverCancel
	}
	f.cfg = cfg
	return nil
}
