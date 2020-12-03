// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"time"

	"fleet/internal/pkg/action"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/env"
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

func runPolicyMon(ctx context.Context, sv saved.CRUD) *PolicyMon {
	pm, err := NewPolicyMon(kPolicyThrottle)
	checkErr(err)

	go func() {
		err := pm.Monitor(ctx, sv)
		checkErr(err)
	}()

	return pm
}

func runActionMon(ctx context.Context, bulker bulk.Bulk) *action.Monitor {
	am, err := action.NewMonitor(bulker)
	if err != nil {
		checkErr(err)
	}

	go func() {
		err := am.Run(ctx)
		checkErr(err)
	}()

	return am
}

func runActionDispatcher(ctx context.Context, am *action.Monitor) *action.Dispatcher {
	ad := action.NewDispatcher(am)

	go func() {
		err := ad.Run(ctx)
		checkErr(err)
	}()

	return ad
}

func installProfiler(ctx context.Context, cfg *config.Server) {
	profile.RunProfiler(ctx, cfg.Profile.Bind)
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

		logger.Init(&cfg.Fleet.Agent.Logging)

		ctx := installSignalHandler()

		installProfiler(ctx, &cfg.Inputs[0].Server)

		checkErr(initGlobalCache())

		es, bulker := InitES(ctx, &cfg.Output.Elasticsearch)

		// Initial indices bootstrapping, needed for agents actions development
		// TODO: remove this after the indices bootstrapping logic implemented in ES plugin
		checkErr(esboot.EnsureESIndices(ctx, es))

		// Start new actions monitoring
		am := runActionMon(ctx, bulker)
		ad := runActionDispatcher(ctx, am)
		tr, err := action.NewTokenResolver(bulker)
		checkErr(err)

		sv := saved.NewMgr(bulker, savedObjectKey())

		pm := runPolicyMon(ctx, sv)
		ba := runBulkActions(ctx, sv)
		bc := runBulkCheckin(ctx, bulker, sv)
		ct := NewCheckinT(bc, ba, pm, am, ad, tr, bulker)
		et := NewEnrollerT(&cfg.Inputs[0].Server, bulker)

		router := NewRouter(ctx, sv, ct, et)

		err = runServer(ctx, router, &cfg.Inputs[0].Server)
		log.Info().Err(err).Msg("Fleet Server exited")

		return nil
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
