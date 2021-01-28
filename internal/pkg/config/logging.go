// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"github.com/rs/zerolog"
	"os"
	"time"
)

// LoggingFiles configuration for the logging file output.
type LoggingFiles struct {
	Path            string        `config:"path"`
	Name            string        `config:"name"`
	MaxSize         uint          `config:"rotateeverybytes" validate:"min=1"`
	MaxBackups      uint          `config:"keepfiles" validate:"max=1024"`
	Permissions     uint32        `config:"permissions"`
	Interval        time.Duration `config:"interval"`
	RotateOnStartup bool          `config:"rotateonstartup"`
	RedirectStderr  bool          `config:"redirect_stderr"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *LoggingFiles) InitDefaults() {
	cwd, err := os.Getwd()
	if err != nil {
		// something really wrong here
		panic(err)
	}

	c.Path = cwd
	c.Name = "fleet-server.log"
	c.MaxSize = 10 * 1024 * 1024
	c.MaxBackups = 7
	c.Permissions = 0600
	c.Interval = 0
	c.RotateOnStartup = true
}

// Logging configuration.
type Logging struct {
	Level    string        `config:"level"`
	ToStderr bool          `config:"to_stderr"`
	ToFiles  bool          `config:"to_files"`
	Files    *LoggingFiles `config:"files"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Logging) InitDefaults() {
	c.Level = "info"
	c.ToFiles = true
}

// Validate ensures that the configuration is valid.
func (c *Logging) Validate() error {
	if _, err := strToLevel(c.Level); err != nil {
		return err
	}
	return nil
}

// LogLevel returns configured zerolog.Level
func (c *Logging) LogLevel() zerolog.Level {
	l, _ := strToLevel(c.Level)
	return l
}
