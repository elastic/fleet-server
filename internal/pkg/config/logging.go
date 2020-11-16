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

package config

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

// Logging is the logging configuration
type Logging struct {
	Destination string `config:"dest"`
	Level       string `config:"level"`
	Pretty      bool   `config:"pretty"`
}

// InitDefaults initializes the defaults for the configuration.
func (c *Logging) InitDefaults() {
	c.Destination = "stdout"
	c.Level = "info"
	c.Pretty = true
}

// Validate ensures that the configuration is valid.
func (c *Logging) Validate() error {
	if _, err := strToDest(c.Destination); err != nil {
		return err
	}
	if _, err := strToLevel(c.Level); err != nil {
		return err
	}
	return nil
}

// DestinationWriter returns configured destination io.Writer
func (c *Logging) DestinationWriter() io.Writer {
	w, _ := strToDest(c.Destination)
	return w
}

// LogLevel returns configured zerolog.Level
func (c *Logging) LogLevel() zerolog.Level {
	l, _ := strToLevel(c.Level)
	return l
}

func strToDest(s string) (io.Writer, error) {
	w := os.Stdout

	s = strings.ToLower(s)
	switch strings.TrimSpace(s) {
	case "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		return w, fmt.Errorf("invalid dest ; must be one of: stdout, stderr")
	}

	return w, nil
}

func strToLevel(s string) (zerolog.Level, error) {
	l := zerolog.DebugLevel

	s = strings.ToLower(s)
	switch strings.TrimSpace(s) {
	case "trace":
		l = zerolog.TraceLevel
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
	default:
		return l, fmt.Errorf("invalid log level; must be one of: trace, info, warn, error, fatal, panic")
	}

	return l, nil
}
