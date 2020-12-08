// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package profile

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/rs/zerolog/log"
)

func RunProfiler(ctx context.Context, addr string) error {

	if addr == "" {
		log.Info().Msg("Profiler disabled")
		return nil
	}

	bctx := func(net.Listener) context.Context { return ctx }

	// Register pprof handlers
	r := http.NewServeMux()
	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := http.Server{
		Addr:        addr,
		Handler:     r,
		BaseContext: bctx,
	}

	log.Info().Str("bind", addr).Msg("Installing profiler")
	if err := server.ListenAndServe(); err != nil {
		log.Error().Err(err).Str("bind", addr).Msg("Fail install profiler")
		return err
	}

	return nil
}
