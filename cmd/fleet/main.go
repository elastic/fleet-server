// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package fleet

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/env"
	"fleet/internal/pkg/esboot"
	"fleet/internal/pkg/logger"
	"fleet/internal/pkg/profile"
	"fleet/internal/pkg/saved"
	"fleet/internal/pkg/signal"
)

var Version string

func checkErr(err error) {
	if err != nil && err != context.Canceled {
		panic(err)
	}
}

func runBulkCheckin(ctx context.Context, bulker bulk.Bulk, sv saved.CRUD) *BulkCheckin {

	bc := NewBulkCheckin()
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
	throttle := env.PolicyThrottle(time.Millisecond * 5)
	pm, err := NewPolicyMon(throttle)
	checkErr(err)

	go func() {
		err := pm.Monitor(ctx, sv)
		checkErr(err)
	}()

	return pm
}

func installProfiler(ctx context.Context) {
	addr := env.ProfileBind("localhost:6060")
	profile.RunProfiler(ctx, addr)
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

		logger.Init(&cfg.Logging)

		ctx := installSignalHandler()

		installProfiler(ctx)

		checkErr(initGlobalCache())

		es, bulker := InitES(ctx)

		// Initial indices bootstrapping, needed for agents actions development
		// TODO: remove this after the indices bootstrapping logic implemented in ES plugin
		checkErr(esboot.EnsureESIndices(ctx, es))

		sv := saved.NewMgr(bulker, savedObjectKey())

		pm := runPolicyMon(ctx, sv)
		ba := runBulkActions(ctx, sv)
		bc := runBulkCheckin(ctx, bulker, sv)
		ct := NewCheckinT(bc, ba, pm)
		et := NewEnrollerT()

		router := NewRouter(ctx, sv, ct, et)

		err = runServer(ctx, router)
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
