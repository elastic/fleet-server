// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	slog "log"
	"net"
	"net/http"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/go-chi/chi/v5"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/zap"
)

type server struct {
	cfg     *config.Server
	addr    string
	handler http.Handler
	logger  *logp.Logger

	connContext func(ctx context.Context, c net.Conn) context.Context // used by OpAMP, if feature is enabled
}

// NewServer creates a new HTTP api for the passed addr.
//
// The server has an http request limit and endpoint specific rate-limits.
// There is also a connection limit that will drop connections if too many connections are formed.
// The underlying API structs (such as *CheckinT) may be shared between servers.
func NewServer(addr string, cfg *config.Server, opts ...APIOpt) *server {
	a := &apiServer{}
	for _, opt := range opts {
		opt(a)
	}

	s := server{
		addr:   addr,
		cfg:    cfg,
		logger: zap.NewStub("api-server"),
	}

	handler := newRouter(&cfg.Limits, a, a.tracer)
	// If OpAMP feature is enabled, add OpAMP route handler to router and
	// let OpAMP server modify connection context (setup later when HTTP server
	// object is constructed).
	if a.oa != nil && a.oa.Enabled() {
		zerolog.Log().Info().Msg("enabling OpAMP endpoint")
		handler = addOpAMPRouteHandler(handler, a.oa, &cfg.Limits)
		s.connContext = a.oa.connCtx
	}

	s.handler = handler
	return &s

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
		ErrorLog:          errLogger(ctx),
		ConnState:         getDiagConnFunc(ctx),
		ConnContext:       s.connContext,
	}

	var listenCfg net.ListenConfig
	ln, err := listenCfg.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	// Bind the deferred Close() to the stack variable to handle case where 'ln' is wrapped
	defer func() {
		err := ln.Close()
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Msg("server.Run: error while closing listener.")
		}
	}()

	// Conn Limiter must be before the TLS handshake in the stack;
	// The server should not eat the cost of the handshake if there
	// is no capacity to service the connection.
	// Also, it appears the HTTP2 implementation depends on the tls.Listener
	// being at the top of the stack.
	ln = wrapConnLimitter(ctx, ln, s.cfg)

	if s.cfg.TLS != nil && s.cfg.TLS.IsEnabled() {
		commonTLSCfg, err := tlscommon.LoadTLSServerConfig(s.cfg.TLS, s.logger)
		if err != nil {
			return err
		}
		srv.TLSConfig = commonTLSCfg.BuildServerConfig(s.cfg.Host)

		// Must enable http/2 in the configuration explicitly.
		// (see https://golang.org/pkg/net/http/#Server.Serve)
		srv.TLSConfig.NextProtos = []string{"h2", "http/1.1"}

		ln = tls.NewListener(ln, srv.TLSConfig)

	} else {
		zerolog.Ctx(ctx).Warn().Msg("Exposed over insecure HTTP; enablement of TLS is strongly recommended")
	}

	// Start the API server on another goroutine and return any non ErrServerClosed errors through a channel.
	errCh := make(chan error)
	go func(ctx context.Context, errCh chan error, ln net.Listener) {
		zerolog.Ctx(ctx).Info().Msgf("Listening on %s", s.addr)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}(ctx, errCh, ln)

	select {
	// Listen and return any errors that occur from the server listener
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			return fmt.Errorf("error while serving API listener: %w", err)
		}
	// Do a clean shutdown if the context is cancelled
	case <-ctx.Done():
		sCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeouts.Drain) // Background context to allow connections to drain when server context is cancelled.
		defer cancel()
		if err := srv.Shutdown(sCtx); err != nil {
			cErr := srv.Close() // force it closed
			return errors.Join(fmt.Errorf("error while shutting down api listener: %w", err), cErr)
		}
	}

	return nil
}

func addOpAMPRouteHandler(existingHandler http.Handler, oa *OpAMPT, cfg *config.ServerLimits) http.Handler {
	r := chi.NewRouter()
	r.Use(Limiter(cfg).middleware)

	opAMPHandler := oa.handler
	r.HandleFunc("/v1/opamp", http.HandlerFunc(opAMPHandler))

	// Handle existing routes
	r.Mount("/", existingHandler)

	return r
}

func getDiagConnFunc(ctx context.Context) func(c net.Conn, s http.ConnState) {
	return func(c net.Conn, s http.ConnState) {
		if c == nil {
			return
		}

		zerolog.Ctx(ctx).Trace().
			Str("local", c.LocalAddr().String()).
			Str("remote", c.RemoteAddr().String()).
			Str("state", s.String()).
			Msg("connection state change")

		switch s {
		case http.StateNew:
			cntHTTPNew.Inc()
			cntHTTPActive.Inc()
		case http.StateClosed:
			cntHTTPClose.Inc()
			cntHTTPActive.Dec()
		}
	}
}

type stubLogger struct {
	log zerolog.Logger
}

func (s *stubLogger) Write(p []byte) (n int, err error) {
	s.log.Error().Bytes(ecs.Message, p).Send()
	return len(p), nil
}

func errLogger(ctx context.Context) *slog.Logger {
	log := zerolog.Ctx(ctx)
	stub := &stubLogger{*log}
	return slog.New(stub, "", 0)
}

// wrapConnLimitter will drop connections once the connection count is max_connections*1.1
// This means that once the limit is reached, the server will resturn 429 responses until the connection count reaches the threshold, then the server will drop connections before the TLS handshake.
func wrapConnLimitter(ctx context.Context, ln net.Listener, cfg *config.Server) net.Listener {
	hardLimit := int(float64(cfg.Limits.MaxConnections) * 1.1)

	if hardLimit != 0 {
		zerolog.Ctx(ctx).Info().
			Int("hardConnLimit", hardLimit).
			Msg("server hard connection limiter installed")

		ln = limit.Listener(ln, hardLimit, zerolog.Ctx(ctx))
	} else {
		zerolog.Ctx(ctx).Info().Msg("server hard connection limiter disabled")
	}

	return ln
}
