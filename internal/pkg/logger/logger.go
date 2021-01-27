// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/elastic/beats/v7/libbeat/common/file"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/reload"
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
	if changed(l.cfg, cfg) {
		// reload the logger
		l, err := configure(cfg)
		if err != nil {
			return err
		}
		log.Logger = l
	}
	l.cfg = cfg
	return nil
}

// Init initializes the logger.
func Init(cfg *config.Config) (reload.Reloadable, error) {
	var err error
	once.Do(func() {
		var l zerolog.Logger
		gLogger = &logger{
			cfg: cfg,
		}

		l, err = configure(cfg)
		if err != nil {
			return
		}
		zerolog.TimeFieldFormat = time.StampMicro
		log.Logger = l
		log.Info().
			Int("pid", os.Getpid()).
			Int("ppid", os.Getppid()).
			Str("exe", os.Args[0]).
			Strs("args", os.Args[1:]).
			Msg("boot")

		log.Debug().Strs("env", os.Environ()).Msg("environment")
	})
	return gLogger, err
}

func changed(a *config.Config, b *config.Config) bool {
	if a.Fleet.Agent.Logging != b.Fleet.Agent.Logging {
		return true
	}
	al := a.Logging
	aFiles := al.Files
	al.Files = nil
	bl := b.Logging
	bFiles := bl.Files
	bl.Files = nil
	if al != bl {
		return true
	}
	if (aFiles == nil && bFiles != nil) || (aFiles != nil && bFiles == nil) || (*aFiles != *bFiles) {
		return true
	}
	return false
}

func level(cfg *config.Config) zerolog.Level {
	if cfg.Fleet.Agent.Logging.Level != "" {
		return cfg.Fleet.Agent.Logging.LogLevel()
	}
	return cfg.Logging.LogLevel()
}

func configure(cfg *config.Config) (zerolog.Logger, error) {
	if cfg.Logging.ToStderr {
		return log.Output(os.Stderr).Level(level(cfg)), nil
	}
	if cfg.Logging.ToFiles {
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
			return zerolog.Logger{}, err
		}
		return log.Output(rotator).Level(level(cfg)), nil
	}
	return log.Output(ioutil.Discard).Level(level(cfg)), nil
}
