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

	go func() {
		log.Info().Str("bind", addr).Msg("Installing profiler")
		if err := server.ListenAndServe(); err != nil {
			log.Error().Err(err).Str("bind", addr).Msg("Fail install profiler")
		}
	}()

	return nil
}
