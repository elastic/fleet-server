// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package zap

import (
	"encoding/json"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"
)

func encoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		MessageKey:     "message",
		LevelKey:       "log.level",
		NameKey:        "log.logger",
		TimeKey:        "@timestamp",
		CallerKey:      "log.origin",
		StacktraceKey:  "log.origin.stack_trace",
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
	m := make(map[string]interface{})
	if err := json.Unmarshal(p, &m); err != nil {
		return 0, err
	}

	e := log.Log()
	for key, val := range m {
		if key != "@timestamp" {
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
