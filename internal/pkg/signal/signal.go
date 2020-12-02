// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
