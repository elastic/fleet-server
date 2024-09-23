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

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/opamp"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"

	"github.com/open-telemetry/opamp-go/protobufs"
	opampserver "github.com/open-telemetry/opamp-go/server"
	"github.com/open-telemetry/opamp-go/server/types"
	"github.com/rs/zerolog"
)

type server struct {
	cfg             *config.Server
	addr            string
	handler         http.Handler
	contextWithConn opampserver.ConnContext
}

// NewServer creates a new HTTP api for the passed addr.
//
// The server has a listener specific conn limit and endpoint specific rate-limits.
// The underlying API structs (such as *CheckinT) may be shared between servers.
func NewServer(addr string, cfg *config.Server, ct *CheckinT, et *EnrollerT, at *ArtifactT, ack *AckT, st *StatusT, sm policy.SelfMonitor, bi build.Info, ut *UploadT, ft *FileDeliveryT, pt *PGPRetrieverT, audit *AuditT, bulker bulk.Bulk, cache cache.Cache, pm policy.Monitor, tracer *apm.Tracer) *server { // this is messy, we have an open issue to refactor
	a := &apiServer{
		ct:     ct,
		et:     et,
		at:     at,
		ack:    ack,
		st:     st,
		sm:     sm,
		bi:     bi,
		ut:     ut,
		ft:     ft,
		pt:     pt,
		audit:  audit,
		bulker: bulker,
	}

	ompampServer := opampserver.New(nil)
	op := opamp.NewHandler(bulker, cache, pm)
	handlerFn, contextWithConn, _ := ompampServer.Attach(opampserver.Settings{
		Callbacks: opampserver.CallbacksStruct{
			OnConnectingFunc: func(request *http.Request) types.ConnectionResponse {
				// NOTE: We don't have an agent ID at this stage so we can only check if the API key is valid.
				agent, err := authAgent(request, nil, bulker, cache)
				if err != nil {
					zerolog.Ctx(request.Context()).Warn().Err(err).Msg("Opamp request api key auth failed.")
					return types.ConnectionResponse{
						Accept:         false,
						HTTPStatusCode: http.StatusUnauthorized,
					}
				}
				return types.ConnectionResponse{
					Accept: true,
					ConnectionCallbacks: opampserver.ConnectionCallbacksStruct{
						OnConnectedFunc: func(ctx context.Context, _ types.Connection) {
							zerolog.Ctx(ctx).Info().Msg("Opamp connection started.")
						},
						OnMessageFunc: func(ctx context.Context, _ types.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
							zerolog.Ctx(ctx).Info().Msg("Opamp message recieved.")
							response, err := op.Process(ctx, agent, message)
							if err != nil {
								zerolog.Ctx(ctx).Error().Err(err).Msg("Error processing opamp request.")
								return &protobufs.ServerToAgent{
									InstanceUid: message.InstanceUid,
									ErrorResponse: &protobufs.ServerErrorResponse{
										ErrorMessage: err.Error(),
									},
								}
							}
							return response
						},
						OnConnectionCloseFunc: func(_ types.Connection) {
							zerolog.Ctx(request.Context()).Info().Msg("Opamp connection ended.") // FIXME getting context from request might be messy
						},
					},
				}

			},
		},
	})

	return &server{
		addr:            addr,
		cfg:             cfg,
		handler:         newRouter(&cfg.Limits, a, tracer, handlerFn),
		contextWithConn: contextWithConn,
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
		ConnState:         diagConn,
		ConnContext:       s.contextWithConn,
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
		sCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeouts.Drain)
		defer cancel()
		if err := srv.Shutdown(sCtx); err != nil {
			cErr := srv.Close() // force it closed
			return errors.Join(fmt.Errorf("error while shutting down api listener: %w", err), cErr)
		}
	}

	return nil
}

func diagConn(c net.Conn, s http.ConnState) {
	if c == nil {
		return
	}

	zerolog.Ctx(context.TODO()).Trace().
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

func wrapConnLimitter(ctx context.Context, ln net.Listener, cfg *config.Server) net.Listener {
	hardLimit := cfg.Limits.MaxConnections

	if hardLimit != 0 {
		zerolog.Ctx(ctx).Info().
			Int("hardConnLimit", hardLimit).
			Msg("server hard connection limiter installed")

		ln = limit.Listener(ln, hardLimit)
	} else {
		zerolog.Ctx(ctx).Info().Msg("server hard connection limiter disabled")
	}

	return ln
}

type stubLogger struct {
	log zerolog.Logger
}

func (s *stubLogger) Write(p []byte) (n int, err error) {
	s.log.Error().Bytes(logger.ECSMessage, p).Send()
	return len(p), nil
}

func errLogger(ctx context.Context) *slog.Logger {
	log := zerolog.Ctx(ctx)
	stub := &stubLogger{*log}
	return slog.New(stub, "", 0)
}
