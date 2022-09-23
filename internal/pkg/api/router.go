// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmhttprouter"
)

const (
	RouteStatus    = "/api/status"
	RouteEnroll    = "/api/fleet/agents/:id"
	RouteCheckin   = "/api/fleet/agents/:id/checkin"
	RouteAcks      = "/api/fleet/agents/:id/acks"
	RouteArtifacts = "/api/fleet/artifacts/:id/:sha2"
)

type Router struct {
	ctx    context.Context // used only by handleEnroll, set at start of Run func
	cfg    *config.Server
	bulker bulk.Bulk
	ct     *CheckinT
	et     *EnrollerT
	at     *ArtifactT
	ack    *AckT
	st     *StatusT
	sm     policy.SelfMonitor
	tracer *apm.Tracer
	bi     build.Info
}

func NewRouter(cfg *config.Server, bulker bulk.Bulk, ct *CheckinT, et *EnrollerT, at *ArtifactT, ack *AckT, st *StatusT, sm policy.SelfMonitor, tracer *apm.Tracer, bi build.Info) *Router {
	rt := &Router{
		cfg:    cfg,
		bulker: bulker,
		ct:     ct,
		et:     et,
		sm:     sm,
		at:     at,
		ack:    ack,
		st:     st,
		tracer: tracer,
		bi:     bi,
	}

	return rt
}

// Create a new httprouter, the passed addr is only added as a label in log messages
func (rt *Router) newHTTPRouter(addr string) *httprouter.Router {
	log.Info().Str("addr", addr).Interface("limits", rt.cfg.Limits).Msg("fleet-server creating new limiter")
	limiter := limit.NewHTTPWrapper(addr, &rt.cfg.Limits)

	routes := []struct {
		method  string
		path    string
		handler httprouter.Handle
	}{
		{
			http.MethodGet,
			RouteStatus,
			limiter.WrapStatus(rt.handleStatus, &cntStatus),
		},
		{
			http.MethodPost,
			RouteEnroll,
			limiter.WrapEnroll(rt.handleEnroll, &cntEnroll),
		},
		{
			http.MethodPost,
			RouteCheckin,
			limiter.WrapCheckin(rt.handleCheckin, &cntCheckin),
		},
		{
			http.MethodPost,
			RouteAcks,
			limiter.WrapAck(rt.handleAcks, &cntAcks),
		},
		{
			http.MethodGet,
			RouteArtifacts,
			limiter.WrapArtifact(rt.handleArtifacts, &cntArtifacts),
		},
	}

	router := httprouter.New()
	// Install routes
	for _, rte := range routes {
		log.Info().
			Str("addr", addr).
			Str("method", rte.method).
			Str("path", rte.path).
			Msg("fleet-server route added")

		handler := rte.handler
		if rt.tracer != nil {
			handler = apmhttprouter.Wrap(
				rte.handler, rte.path, apmhttprouter.WithTracer(rt.tracer),
			)
		}
		router.Handle(
			rte.method,
			rte.path,
			logger.HTTPHandler(handler),
		)
	}
	log.Info().Str("addr", addr).Msg("fleet-server routes set up")
	return router
}

// Run starts the api server on the listeners configured in the config.
// Each listener has a unique limit.Limiter to allow for non-global rate limits.
func (rt *Router) Run(ctx context.Context) error {
	rt.ctx = ctx

	listeners := rt.cfg.BindEndpoints()
	rdto := rt.cfg.Timeouts.Read
	wrto := rt.cfg.Timeouts.Write
	idle := rt.cfg.Timeouts.Idle
	rdhr := rt.cfg.Timeouts.ReadHeader
	mhbz := rt.cfg.Limits.MaxHeaderByteSize
	bctx := func(net.Listener) context.Context { return ctx }

	errChan := make(chan error)
	baseCtx, cancel := context.WithCancel(ctx)
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
			Handler:           rt.newHTTPRouter(addr), // Note that we use a different router for each listener instead of wrapping with different middleware instances as it is cleaner to do
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
				err := server.Close()
				if err != nil {
					log.Error().Err(err).Msg("error while closing server")
				}
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
		ln = wrapConnLimitter(ctx, ln, rt.cfg)

		if rt.cfg.TLS != nil && rt.cfg.TLS.IsEnabled() {
			commonTLSCfg, err := tlscommon.LoadTLSServerConfig(rt.cfg.TLS)
			if err != nil {
				return err
			}
			server.TLSConfig = commonTLSCfg.BuildServerConfig(rt.cfg.Host)

			// Must enable http/2 in the configuration explicitly.
			// (see https://golang.org/pkg/net/http/#Server.Serve)
			server.TLSConfig.NextProtos = []string{"h2", "http/1.1"}

			ln = tls.NewListener(ln, server.TLSConfig)

		} else {
			log.Warn().Msg("Exposed over insecure HTTP; enablement of TLS is strongly recommended")
		}

		log.Debug().Msgf("Listening on %s", addr)

		go func(_ context.Context, errChan chan error, ln net.Listener) {
			if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- err
			}
		}(baseCtx, errChan, ln)

	}

	select {
	case err := <-errChan:
		if !errors.Is(err, context.Canceled) {
			return err
		}
	case <-baseCtx.Done():
	}

	return nil
}
