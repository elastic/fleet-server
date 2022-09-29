// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package fleet is the main entry point for fleet-server.
package fleet

import (
	"context"
	"errors"
	"os"

	"go.elastic.co/apm"

	"github.com/elastic/go-ucfg/yaml"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/server"
	"github.com/elastic/fleet-server/v7/internal/pkg/signal"
	"github.com/elastic/fleet-server/v7/internal/pkg/status"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	kAgentMode = "agent-mode"
)

func init() {
	// Close default apm tracer.
	apm.DefaultTracer.Close()
}

func installSignalHandler() context.Context {
	rootCtx := context.Background()
	return signal.HandleInterrupt(rootCtx)
}

func initLogger(cfg *config.Config, version, commit string) (*logger.Logger, error) {
	l, err := logger.Init(cfg, build.ServiceName)
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
		Msg("Boot fleet-server")
	log.Debug().Strs("env", os.Environ()).Msg("environment")

	return l, err
}

func getRunCommand(bi build.Info) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		cfgObject := cmd.Flags().Lookup("E").Value.(*config.Flag) //nolint:errcheck // we know the flag exists
		cliCfg := cfgObject.Config()

		agentMode, err := cmd.Flags().GetBool(kAgentMode)
		if err != nil {
			return err
		}

		var l *logger.Logger
		var srv server.Server
		if agentMode {
			cfg, err := config.FromConfig(cliCfg)
			if err != nil {
				return err
			}
			l, err = initLogger(cfg, bi.Version, bi.Commit)
			if err != nil {
				return err
			}

			srv, err = server.NewAgent(cliCfg, os.Stdin, bi, l)
			if err != nil {
				return err
			}
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

			l, err = initLogger(cfg, bi.Version, bi.Commit)
			if err != nil {
				return err
			}

			srv, err = server.NewFleet(cfg, bi, status.NewLog())
			if err != nil {
				return err
			}
		}

		if err := srv.Run(installSignalHandler()); err != nil && !errors.Is(err, context.Canceled) {
			log.Error().Err(err).Msg("Exiting")
			l.Sync()
			return err
		}
		l.Sync()
		return nil
	}
}

func NewCommand(bi build.Info) *cobra.Command {
	cmd := &cobra.Command{
		Use:   build.ServiceName,
		Short: "Fleet Server controls a fleet of Elastic Agents",
		RunE:  getRunCommand(bi),
	}
	cmd.Flags().StringP("config", "c", "fleet-server.yml", "Configuration for Fleet Server")
	cmd.Flags().Bool(kAgentMode, false, "Running under execution of the Elastic Agent")
	cmd.Flags().VarP(config.NewFlag(), "E", "E", "Overwrite configuration value")
	return cmd
}
