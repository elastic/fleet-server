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

package logger

import (
	"fleet/internal/pkg/config"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

func Init(cfg *config.Logging) {
	zerolog.TimeFieldFormat = time.StampMicro

	if cfg.Pretty {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        cfg.DestinationWriter(),
			TimeFormat: kPrettyTimeFormat,
		}).Level(cfg.LogLevel())
	} else {
		log.Logger = log.Output(cfg.DestinationWriter()).Level(cfg.LogLevel())
	}

	log.Info().
		Int("pid", os.Getpid()).
		Int("ppid", os.Getppid()).
		Str("exe", os.Args[0]).
		Strs("args", os.Args[1:]).
		Msg("boot")

	log.Debug().Strs("env", os.Environ()).Msg("environment")
}
