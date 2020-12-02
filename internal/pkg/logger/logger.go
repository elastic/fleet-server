// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"fleet/internal/pkg/config"
)

const (
	kPrettyTimeFormat = "15:04:05.000000"
)

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

func Init(cfg *config.AgentLogging) {
	zerolog.TimeFieldFormat = time.StampMicro

	log.Logger = log.Output(os.Stdout).Level(cfg.LogLevel())
	log.Info().
		Int("pid", os.Getpid()).
		Int("ppid", os.Getppid()).
		Str("exe", os.Args[0]).
		Strs("args", os.Args[1:]).
		Msg("boot")

	log.Debug().Strs("env", os.Environ()).Msg("environment")
}
