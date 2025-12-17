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

	"github.com/go-chi/chi/v5"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"

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
	handler := newRouter(&cfg.Limits, a, a.tracer)

	// Add OpAmp endpoint if enabled and handler is configured
	if a.ot != nil && a.ot.IsEnabled() {
		handler = addOpAmpRoute(handler, a.ot)
	}

	return &server{
		addr:    addr,
		cfg:     cfg,
		handler: handler,
		logger:  zap.NewStub("api-server"),
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
		ErrorLog:          errLogger(ctx),
		ConnState:         getDiagConnFunc(ctx),
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

// addOpAmpRoute wraps the existing handler and adds the OpAmp endpoint
func addOpAmpRoute(handler http.Handler, ot *OpAmpT) http.Handler {
	r := chi.NewRouter()

	// Mount the OpAmp handler at its configured path
	opampHandler, err := ot.GetHTTPHandler()
	if err != nil {
		// Log error and return original handler without OpAmp
		zerolog.Ctx(context.Background()).Error().Err(err).Msg("Failed to create OpAmp handler")
		return handler
	}

	path := ot.GetPath()
	r.Post(path, opampHandler)

	// Mount the existing handler for all other routes
	r.Mount("/", handler)

	return r
}
