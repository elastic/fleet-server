// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package fleet

import (
	"context"
	"fleet/internal/pkg/config"
	slog "log"
	"net"
	"net/http"

	"fleet/internal/pkg/rate"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

func diagConn(c net.Conn, s http.ConnState) {
	log.Trace().
		Str("local", c.LocalAddr().String()).
		Str("remote", c.RemoteAddr().String()).
		Str("state", s.String()).
		Msg("connection state change")
}

func runServer(ctx context.Context, router *httprouter.Router, cfg *config.Server) error {

	addr := cfg.Host
	rdto := cfg.Timeouts.Read
	wrto := cfg.Timeouts.Write
	mhbz := cfg.MaxHeaderByteSize
	bctx := func(net.Listener) context.Context { return ctx }

	log.Info().
		Str("bind", addr).
		Dur("rdTimeout", rdto).
		Dur("wrTimeout", wrto).
		Msg("Server listening")

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
			log.Debug().Msg("Force server close on ctx.Done()")
			server.Close()
		case <-forceCh:
			log.Debug().Msg("Go routine forced closed on exit")
		}
	}()

	ln, err := makeListener(ctx, addr, cfg)
	if err != nil {
		return err
	}

	defer ln.Close()

	// TODO: Use tls.Config to properly lock down tls connection
	keyFile := cfg.TLS.Key
	certFile := cfg.TLS.Cert

	if keyFile != "" || certFile != "" {
		return server.ServeTLS(ln, certFile, keyFile)
	}

	return server.Serve(ln)
}

func makeListener(ctx context.Context, addr string, cfg *config.Server) (net.Listener, error) {
	// Create listener
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	rateLimitBurst := cfg.RateLimitBurst
	rateLimitInterval := cfg.RateLimitInterval

	if rateLimitInterval != 0 {
		log.Info().Dur("interval", rateLimitInterval).Int("burst", rateLimitBurst).Msg("Server rate limiter installed")
		ln = rate.NewRateListener(ctx, ln, rateLimitBurst, rateLimitInterval)
	} else {
		log.Info().Msg("Server connection rate limiter disabled")
	}

	return ln, err
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
