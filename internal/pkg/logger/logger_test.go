// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:goconst // used in tests
package logger

import (
	"bytes"
	"context"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stderrcfg() *config.Config {
	cfg := &config.Config{}
	cfg.InitDefaults()
	cfg.Logging.ToStderr = true
	cfg.Logging.ToFiles = false
	return cfg
}

func TestLoggerDefaultLevel(t *testing.T) {
	cfg := stderrcfg()
	l := level(cfg)
	assert.Empty(t, cfg.Fleet.Agent.Logging.Level)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, zerolog.InfoLevel, l, "expected info got %s", l)
}

func Test_Logger_Reload(t *testing.T) {
	logger, err := Init(stderrcfg(), "test")
	require.NoError(t, err)

	t.Run("no changes", func(t *testing.T) {
		var b bytes.Buffer
		log.Logger = zerolog.New(&b)
		logger.cfg = stderrcfg()
		logger.sync = &nopSync{}

		err := logger.Reload(context.Background(), stderrcfg())
		require.NoError(t, err)
		log.Info().Msg("Hello, World!")

		assert.Equal(t, zerolog.InfoLevel, zerolog.GlobalLevel())
		assert.NotEmpty(t, b, "expected something to be written")
	})

	t.Run("only level change", func(t *testing.T) {
		var b bytes.Buffer
		log.Logger = zerolog.New(&b)
		logger.cfg = stderrcfg()
		logger.sync = &nopSync{}

		cfg := stderrcfg()
		cfg.Logging.Level = "debug"
		err := logger.Reload(context.Background(), cfg)
		require.NoError(t, err)
		log.Info().Msg("Hello, World!")

		assert.Equal(t, zerolog.DebugLevel, zerolog.GlobalLevel())
		assert.NotEmpty(t, b, "expected something to be written")
	})

	t.Run("only other change", func(t *testing.T) {
		var b bytes.Buffer
		log.Logger = zerolog.New(&b)
		logger.cfg = stderrcfg()
		logger.sync = &nopSync{}

		cfg := stderrcfg()
		cfg.Logging.ToStderr = false
		err := logger.Reload(context.Background(), cfg)
		require.NoError(t, err)
		log.Info().Msg("Hello, World!")

		assert.Equal(t, zerolog.InfoLevel, zerolog.GlobalLevel())
		assert.Empty(t, b, "write went to original logger")
	})

	t.Run("both level and other change", func(t *testing.T) {
		var b bytes.Buffer
		log.Logger = zerolog.New(&b)
		logger.cfg = stderrcfg()
		logger.sync = &nopSync{}

		cfg := stderrcfg()
		cfg.Logging.ToStderr = false
		cfg.Logging.Level = "warn"
		err := logger.Reload(context.Background(), cfg)
		require.NoError(t, err)
		log.Info().Msg("Hello, World!")

		assert.Equal(t, zerolog.WarnLevel, zerolog.GlobalLevel())
		assert.Empty(t, b, "write went to original logger")
	})
	t.Run("Check context logger", func(t *testing.T) {
		var b bytes.Buffer
		l := zerolog.New(&b)
		zerolog.DefaultContextLogger = &l
		logger.cfg = stderrcfg()
		logger.sync = &nopSync{}

		zerolog.Ctx(context.Background()).Error().Msg("Hello, World!")
		assert.NotEmpty(t, b, "expected something to be written")
		b.Reset()

		cfg := stderrcfg()
		cfg.Logging.Level = "debug"
		err := logger.Reload(context.Background(), cfg)
		require.NoError(t, err)
		zerolog.Ctx(context.Background()).Error().Msg("Hello, World!")

		assert.Equal(t, zerolog.DebugLevel, zerolog.GlobalLevel())
		assert.NotEmpty(t, b, "expected something to be written")
	})
}
