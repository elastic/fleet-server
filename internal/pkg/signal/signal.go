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

package signal

import (
	"context"
	"github.com/rs/zerolog/log"
	"os"
	"os/signal"
	"syscall"
)

func HandleInterrupt(ctx context.Context) context.Context {
	ctx, cfunc := context.WithCancel(ctx)

	log.Debug().Msg("Install signal handlers for SIGINT and SIGTERM")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-sigs:
			log.Info().Str("sig", sig.String()).Msg("On signal")
			cfunc()
		case <-ctx.Done():
			log.Debug().Msg("Shutdown context done")
		}

		signal.Stop(sigs)
		close(sigs)

		log.Debug().Msg("Signal handler close")
	}()

	return ctx
}
