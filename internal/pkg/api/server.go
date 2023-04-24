// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"crypto/tls"
	"errors"
	slog "log"
	"net"
	"net/http"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"go.elastic.co/apm/v2"

	"github.com/rs/zerolog/log"
)

type server struct {
	cfg     *config.Server
	addr    string
	handler http.Handler
}

// NewServer creates a new HTTP api for the passed addr.
//
// The server has a listener specific conn limit and endpoint specific rate-limits.
// The underlying API structs (such as *CheckinT) may be shared between servers.
func NewServer(addr string, cfg *config.Server, ct *CheckinT, et *EnrollerT, at *ArtifactT, ack *AckT, st *StatusT, sm policy.SelfMonitor, bi build.Info, ut *UploadT, bulker bulk.Bulk, tracer *apm.Tracer) *server {
	a := &apiServer{
		ct:     ct,
		et:     et,
		at:     at,
		ack:    ack,
		st:     st,
		sm:     sm,
		bi:     bi,
		ut:     ut,
		bulker: bulker,
	}
	return &server{
		addr:    addr,
		cfg:     cfg,
		handler: newRouter(&cfg.Limits, a, tracer),
	}
}

func (s *server) Run(ctx context.Context) error {
	rdto := s.cfg.Timeouts.Read
	wrto := s.cfg.Timeouts.Write
	idle := s.cfg.Timeouts.Idle
	rdhr := s.cfg.Timeouts.ReadHeader
	mhbz := s.cfg.Limits.MaxHeaderByteSize

	srv := http.Server{
		Addr:              s.addr,
		Handler:           s.handler,
		ReadTimeout:       rdto,
		ReadHeaderTimeout: rdhr,
		WriteTimeout:      wrto,
		IdleTimeout:       idle,
		MaxHeaderBytes:    mhbz,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          errLogger(),
		ConnState:         diagConn,
	}

	forceCh := make(chan struct{})
	defer close(forceCh)

	// handler to close server
	go func() {
		select {
		case <-ctx.Done():
			log.Debug().Msg("force server close on ctx.Done()")
			err := srv.Close()
			if err != nil {
				log.Error().Err(err).Msg("error while closing server")
			}
		case <-forceCh:
			log.Debug().Msg("go routine forced closed on exit")
		}
	}()

	var listenCfg net.ListenConfig

	ln, err := listenCfg.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	// Bind the deferred Close() to the stack variable to handle case where 'ln' is wrapped
	defer func() {
		err := ln.Close()
		if err != nil {
			log.Error().Err(err).Msg("error while closing listener.")
		}
	}()

	// Conn Limiter must be before the TLS handshake in the stack;
	// The server should not eat the cost of the handshake if there
	// is no capacity to service the connection.
	// Also, it appears the HTTP2 implementation depends on the tls.Listener
	// being at the top of the stack.
	ln = wrapConnLimitter(ctx, ln, s.cfg)

	if s.cfg.TLS != nil && s.cfg.TLS.IsEnabled() {
		commonTLSCfg, err := tlscommon.LoadTLSServerConfig(s.cfg.TLS)
		if err != nil {
			return err
		}
		srv.TLSConfig = commonTLSCfg.BuildServerConfig(s.cfg.Host)

		// Must enable http/2 in the configuration explicitly.
		// (see https://golang.org/pkg/net/http/#Server.Serve)
		srv.TLSConfig.NextProtos = []string{"h2", "http/1.1"}

		ln = tls.NewListener(ln, srv.TLSConfig)

	} else {
		log.Warn().Msg("Exposed over insecure HTTP; enablement of TLS is strongly recommended")
	}

	errCh := make(chan error)
	baseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func(_ context.Context, errCh chan error, ln net.Listener) {
		log.Info().Msgf("Listening on %s", s.addr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}(baseCtx, errCh, ln)

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			return err
		}
	case <-baseCtx.Done():
	}

	return nil
}

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
