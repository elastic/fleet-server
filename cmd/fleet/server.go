// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"crypto/tls"
	slog "log"
	"net"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"

	"github.com/elastic/beats/v7/libbeat/common/transport/tlscommon"
	"github.com/julienschmidt/httprouter"
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
		cntHttpNew.Inc()
	case http.StateClosed:
		cntHttpClose.Inc()
	}
}

func runServer(ctx context.Context, router *httprouter.Router, cfg *config.Server) error {

	listeners := cfg.BindEndpoints()
	rdto := cfg.Timeouts.Read
	wrto := cfg.Timeouts.Write
	idle := cfg.Timeouts.Idle
	rdhr := cfg.Timeouts.ReadHeader
	mhbz := cfg.Limits.MaxHeaderByteSize
	bctx := func(net.Listener) context.Context { return ctx }

	errChan := make(chan error)
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, addr := range listeners {
		log.Info().
			Str("bind", addr).
			Dur("rdTimeout", rdto).
			Dur("wrTimeout", wrto).
			Msg("server listening")

		server := http.Server{
			Addr:              addr,
			ReadTimeout:       rdto,
			WriteTimeout:      wrto,
			IdleTimeout:       idle,
			ReadHeaderTimeout: rdhr,
			Handler:           router,
			BaseContext:       bctx,
			ConnState:         diagConn,
			MaxHeaderBytes:    mhbz,
			ErrorLog:          errLogger(),
		}

		forceCh := make(chan struct{})
		defer close(forceCh)

		// handler to close server
		go func() {
			select {
			case <-ctx.Done():
				log.Debug().Msg("force server close on ctx.Done()")
				server.Close()
			case <-forceCh:
				log.Debug().Msg("go routine forced closed on exit")
			}
		}()

		var listenCfg net.ListenConfig

		ln, err := listenCfg.Listen(ctx, "tcp", addr)
		if err != nil {
			return err
		}

		// Bind the deferred Close() to the stack variable to handle case where 'ln' is wrapped
		defer func() { ln.Close() }()

		// Conn Limiter must be before the TLS handshake in the stack;
		// The server should not eat the cost of the handshake if there
		// is no capacity to service the connection.
		// Also, it appears the HTTP2 implementation depends on the tls.Listener
		// being at the top of the stack.
		ln = wrapConnLimitter(ctx, ln, cfg)

		if cfg.TLS != nil && cfg.TLS.IsEnabled() {
			commonTlsCfg, err := tlscommon.LoadTLSServerConfig(cfg.TLS)
			if err != nil {
				return err
			}
			server.TLSConfig = commonTlsCfg.ToConfig()

			// Must enable http/2 in the configuration explicitly.
			// (see https://golang.org/pkg/net/http/#Server.Serve)
			server.TLSConfig.NextProtos = []string{"h2", "http/1.1"}

			ln = tls.NewListener(ln, server.TLSConfig)

		} else {
			log.Warn().Msg("Exposed over insecure HTTP; enablement of TLS is strongly recommended")
		}

		log.Debug().Msgf("Listening on %s", addr)

		go func(ctx context.Context, errChan chan error, ln net.Listener) {
			if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
				errChan <- err
			}
		}(cancelCtx, errChan, ln)

	}

	select {
	case err := <-errChan:
		if err != context.Canceled {
			return err
		}
	case <-cancelCtx.Done():
	}

	return nil
}

func wrapConnLimitter(ctx context.Context, ln net.Listener, cfg *config.Server) net.Listener {
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
	log.Error().Bytes(logger.EcsMessage, p).Send()
	return len(p), nil
}

func errLogger() *slog.Logger {
	stub := &stubLogger{}
	return slog.New(stub, "", 0)
}
