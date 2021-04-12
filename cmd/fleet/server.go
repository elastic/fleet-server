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

	"github.com/elastic/beats/v7/libbeat/common/transport/tlscommon"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/netutil"
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

	addr := cfg.BindAddress()
	rdto := cfg.Timeouts.Read
	wrto := cfg.Timeouts.Write
	mhbz := cfg.Limits.MaxHeaderByteSize
	bctx := func(net.Listener) context.Context { return ctx }

	log.Info().
		Str("bind", addr).
		Dur("rdTimeout", rdto).
		Dur("wrTimeout", wrto).
		Msg("server listening")

	server := http.Server{
		Addr:           addr,
		ReadTimeout:    rdto,
		WriteTimeout:   wrto,
		Handler:        router,
		BaseContext:    bctx,
		ConnState:      diagConn,
		MaxHeaderBytes: mhbz,
		ErrorLog:       errLogger(),
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

	defer ln.Close()

	if cfg.TLS != nil && cfg.TLS.IsEnabled() {
		tlsCfg, err := tlscommon.LoadTLSConfig(cfg.TLS)
		if err != nil {
			return err
		}
		server.TLSConfig = tlsCfg.ToConfig()
		ln = tls.NewListener(ln, server.TLSConfig)
	} else {
		log.Warn().Msg("exposed over insecure HTTP; enablement of TLS is strongly recommended")
	}

	ln = wrapConnLimitter(ctx, ln, cfg)
	if err := server.Serve(ln); err != nil && err != context.Canceled {
		return err
	}

	return nil
}

func wrapConnLimitter(ctx context.Context, ln net.Listener, cfg *config.Server) net.Listener {
	hardLimit := cfg.Limits.MaxConnections

	if hardLimit != 0 {
		log.Info().
			Int("hardConnLimit", hardLimit).
			Msg("server hard connection limiter installed")

		ln = netutil.LimitListener(ln, hardLimit)
	} else {
		log.Info().Msg("server hard connection limiter disabled")
	}

	return ln
}

type stubLogger struct {
}

func (s *stubLogger) Write(p []byte) (n int, err error) {
	log.Error().Bytes("msg", p).Send()
	return len(p), nil
}

func errLogger() *slog.Logger {
	stub := &stubLogger{}
	return slog.New(stub, "", 0)
}
