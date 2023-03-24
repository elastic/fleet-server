// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestDefaultLevel(t *testing.T) {
	cfg := Logging{}
	cfg.InitDefaults()

	if cfg.LogLevel() != zerolog.InfoLevel {
		t.Errorf("expected InfoLevel, got %s", cfg.LogLevel())
	}
}

func Test_Logging_EqualExcludeLevel(t *testing.T) {
	testcases := []struct {
		name string
		cfg  Logging
		eq   bool
	}{{
		name: "equal",
		cfg: Logging{
			Files: &LoggingFiles{
				Path:        "testdir",
				Name:        "testfile",
				MaxSize:     1024,
				MaxBackups:  2,
				Permissions: 0600,
				Interval:    time.Second,
			},
		},
		eq: true,
	}, {
		name: "ToStderr does not match",
		cfg: Logging{
			ToStderr: true,
			Files: &LoggingFiles{
				Path:        "testdir",
				Name:        "testfile",
				MaxSize:     1024,
				MaxBackups:  2,
				Permissions: 0600,
				Interval:    time.Second,
			},
		},
		eq: false,
	}, {
		name: "ToFiles does not match",
		cfg: Logging{
			ToFiles: true,
			Files: &LoggingFiles{
				Path:        "testdir",
				Name:        "testfile",
				MaxSize:     1024,
				MaxBackups:  2,
				Permissions: 0600,
				Interval:    time.Second,
			},
		},
		eq: false,
	}, {
		name: "Pretty does not match",
		cfg: Logging{
			Pretty: true,
			Files: &LoggingFiles{
				Path:        "testdir",
				Name:        "testfile",
				MaxSize:     1024,
				MaxBackups:  2,
				Permissions: 0600,
				Interval:    time.Second,
			},
		},
		eq: false,
	}, {
		name: "compared with nil files",
		cfg:  Logging{},
		eq:   false,
	}, {
		name: "files do not match",
		cfg: Logging{
			Files: &LoggingFiles{
				Path:            "testdir",
				Name:            "testfile",
				MaxSize:         1024,
				MaxBackups:      2,
				Permissions:     0600,
				Interval:        time.Second,
				RotateOnStartup: true,
			},
		},
		eq: false,
	}}
	cfg := Logging{
		Files: &LoggingFiles{
			Path:        "testdir",
			Name:        "testfile",
			MaxSize:     1024,
			MaxBackups:  2,
			Permissions: 0600,
			Interval:    time.Second,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.eq, cfg.EqualExcludeLevel(tc.cfg), "expected equal: %v cfg: %v cmp: %v", tc.eq, cfg, tc.cfg)
		})
	}

	t.Run("both files nil", func(t *testing.T) {
		a := &Logging{}
		b := Logging{}
		assert.True(t, a.EqualExcludeLevel(b))
	})

	t.Run("level does not match", func(t *testing.T) {
		a := &Logging{
			Level: "info",
		}
		b := Logging{
			Level: "debug",
		}
		assert.True(t, a.EqualExcludeLevel(b))
	})
}
