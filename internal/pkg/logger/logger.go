// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package logger provides logging utilities for fleet-server.
// Currently it wraps rs/zerolog
package logger

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"

	"go.elastic.co/ecszerolog"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
)

var once sync.Once
var gLogger *Logger

// WriterSync implements a Sync function.
type WriterSync interface {
	// Sync syncs the logger to its output.
	Sync() error
}

// Logger for the Fleet Server.
//
// Logger will manage the zerolog/log.Logger variable.
// An instance with TraceLevel is always created and log level is controlled through zerolog.GlobalLevel.
type Logger struct {
	cfg  *config.Config
	sync WriterSync
	name string
	log  zerolog.Logger
}

// Reload reloads the logger configuration.
// If only the log level has changed then only GlobalLogLevel is set.
func (l *Logger) Reload(_ context.Context, cfg *config.Config) error {
	if levelChanged(cfg) {
		zerolog.SetGlobalLevel(level(cfg))
	}
	if !l.cfg.Logging.EqualExcludeLevel(cfg.Logging) {
		// sync before set
		l.Sync()

		out, wr, err := getOutput(cfg)
		if err != nil {
			return err
		}
		l.log = l.log.Output(out)
		l.sync = wr

		log.Logger = l.log
		zerolog.DefaultContextLogger = &l.log // introduces race conditions in integration test?
	}
	l.cfg = cfg
	return nil
}

// Sync syncs the logger to its output.
func (l *Logger) Sync() {
	if l.sync != nil {
		l.sync.Sync() //nolint: errcheck // nowhere to report an error
	}
}

// Init initializes the logger.
func Init(cfg *config.Config, svcName string) (*Logger, error) {
	var err error
	once.Do(func() {
		zerolog.SetGlobalLevel(level(cfg))

		out, wr, err := getOutput(cfg)
		if err != nil {
			return
		}
		l := ecszerolog.New(out)
		if svcName != "" {
			l = l.With().Str(ECSServiceName, svcName).Str(ECSServiceType, svcName).Logger()
		}

		log.Logger = l
		zerolog.DefaultContextLogger = &l
		gLogger = &Logger{
			cfg:  cfg,
			sync: wr,
			name: svcName,
			log:  l,
		}
	})
	return gLogger, err
}

func levelChanged(cfg *config.Config) bool {
	return level(cfg) != zerolog.GlobalLevel()
}

func level(cfg *config.Config) zerolog.Level {
	return cfg.Logging.LogLevel()
}

func stderrOut(cfg *config.Config) (io.Writer, WriterSync) {
	out := io.Writer(os.Stderr)
	if cfg.Logging.Pretty {
		out = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05.000"}
	}

	return out, os.Stderr
}

func fileRotatorOut(cfg *config.Config) (io.Writer, WriterSync, error) {
	files := cfg.Logging.Files
	if files == nil {
		files = &config.LoggingFiles{}
		files.InitDefaults()
	}
	filename := filepath.Join(files.Path, files.Name)
	rotator, err := file.NewFileRotator(filename,
		file.MaxSizeBytes(files.MaxSize),
		file.MaxBackups(files.MaxBackups),
		file.Permissions(os.FileMode(files.Permissions)),
		file.Interval(files.Interval),
		file.RotateOnStartup(files.RotateOnStartup),
		file.RedirectStderr(files.RedirectStderr),
	)
	if err != nil {
		return nil, nil, err
	}
	return rotator, rotator, nil
}

func getOutput(cfg *config.Config) (out io.Writer, wr WriterSync, err error) {
	switch {
	case cfg.Logging.ToStderr:
		out, wr = stderrOut(cfg)
	case cfg.Logging.ToFiles:
		out, wr, err = fileRotatorOut(cfg)
	default:
		out = io.Discard
		wr = &nopSync{}
	}

	return //nolint:nakedret // short function
}

type nopSync struct {
}

// Sync does nothing.
func (*nopSync) Sync() error {
	return nil
}
