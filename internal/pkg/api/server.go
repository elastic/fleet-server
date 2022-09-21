// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	slog "log"
	"net"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"

	"github.com/rs/zerolog/log"
)

func diagConn(c net.Conn, s http.ConnState) {
	if c == nil {
		return
	}

	log.Trace().
		Str("local", c.LocalAddr().String()).
		Str("remote", c.RemoteAddr().String()).
		Str("state", s.String()).
		Msg("connection state change")

	switch s {
	case http.StateNew:
		cntHTTPNew.Inc()
	case http.StateClosed:
		cntHTTPClose.Inc()
	}
}

func wrapConnLimitter(_ context.Context, ln net.Listener, cfg *config.Server) net.Listener {
	hardLimit := cfg.Limits.MaxConnections

	if hardLimit != 0 {
		log.Info().
			Int("hardConnLimit", hardLimit).
			Msg("server hard connection limiter installed")

		ln = limit.Listener(ln, hardLimit)
	} else {
		log.Info().Msg("server hard connection limiter disabled")
	}

	return ln
}

type stubLogger struct {
}

func (s *stubLogger) Write(p []byte) (n int, err error) {
	log.Error().Bytes(logger.ECSMessage, p).Send()
	return len(p), nil
}

func errLogger() *slog.Logger {
	stub := &stubLogger{}
	return slog.New(stub, "", 0)
}
