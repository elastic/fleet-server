// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package zap

import (
	"encoding/json"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
)

func encoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		MessageKey:     ecs.ECSMessage,
		LevelKey:       ecs.ECSLogLevel,
		NameKey:        ecs.ECSLogName,
		TimeKey:        ecs.ECSTimestamp,
		CallerKey:      ecs.ECSLogCaller,
		StacktraceKey:  ecs.ECSLogStackTrace,
		LineEnding:     "\n",
		EncodeTime:     zapcore.EpochTimeEncoder,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeDuration: zapcore.NanosDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
}

type zapStub struct {
}

func (z zapStub) Enabled(zapLevel zapcore.Level) bool {
	zeroLevel := log.Logger.GetLevel()

	switch zapLevel {
	case zapcore.DebugLevel:
		return zeroLevel == zerolog.DebugLevel
	case zapcore.InfoLevel:
		return zeroLevel <= zerolog.InfoLevel
	case zapcore.WarnLevel:
		return zeroLevel <= zerolog.WarnLevel
	case zapcore.ErrorLevel:
		return zeroLevel <= zerolog.ErrorLevel
	case zapcore.FatalLevel:
		return zeroLevel <= zerolog.FatalLevel
	case zapcore.DPanicLevel, zapcore.PanicLevel:
		return zeroLevel <= zerolog.PanicLevel
	}

	return true
}

func (z zapStub) Sync() error {
	return nil
}

func (z zapStub) Write(p []byte) (n int, err error) {
	// Unwrap the zap object for logging
	m := make(map[string]interface{})
	if err := json.Unmarshal(p, &m); err != nil {
		return 0, err
	}

	e := log.Log()
	for key, val := range m {

		// Don't dupe the timestamp, use the fleet formatted timestamp.
		if key != ecs.ECSTimestamp {
			e.Interface(key, val)
		}
	}

	e.Send()
	return 0, nil
}

func NewStub(selector string) *logp.Logger {

	wrapF := func(zapcore.Core) zapcore.Core {
		enc := zapcore.NewJSONEncoder(encoderConfig())
		stub := zapStub{}
		return zapcore.NewCore(enc, stub, stub)
	}

	return logp.NewLogger(selector, zap.WrapCore(wrapF))
}
