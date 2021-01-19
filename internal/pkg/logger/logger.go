// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"context"
	"github.com/elastic/fleet-server/v7/internal/pkg/reload"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
)

const (
	kPrettyTimeFormat = "15:04:05.000000"
)

var once sync.Once
var gLogger *logger

func strToLevel(s string) zerolog.Level {
	l := zerolog.DebugLevel

	s = strings.ToLower(s)
	switch strings.TrimSpace(s) {
	case "trace":
		l = zerolog.TraceLevel
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warn":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	case "fatal":
		l = zerolog.FatalLevel
	case "panic":
		l = zerolog.PanicLevel
	}

	return l
}

type logger struct {
	cfg *config.Config
}

// Reload reloads the logger configuration.
func (l *logger) Reload(_ context.Context, cfg *config.Config) error {
	if l.cfg.Fleet.Agent.Logging != cfg.Fleet.Agent.Logging {
		// reload the logger to new config level
		log.Logger = log.Output(os.Stdout).Level(cfg.Fleet.Agent.Logging.LogLevel())
	}
	l.cfg = cfg
	return nil
}

// Init initializes the logger.
func Init(cfg *config.Config) reload.Reloadable {
	once.Do(func() {
		gLogger = &logger{
			cfg: cfg,
		}

		zerolog.TimeFieldFormat = time.StampMicro

		log.Logger = log.Output(os.Stdout).Level(cfg.Fleet.Agent.Logging.LogLevel())
		log.Info().
			Int("pid", os.Getpid()).
			Int("ppid", os.Getppid()).
			Str("exe", os.Args[0]).
			Strs("args", os.Args[1:]).
			Msg("boot")

		log.Debug().Strs("env", os.Environ()).Msg("environment")
	})
	return gLogger
}
