// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type RunFunc func(context.Context) error
type DoneFunc func(err error)

func Start(ctx context.Context, wg *sync.WaitGroup, runfn RunFunc, donefn DoneFunc) {
	wg.Add(1)

	go func() {
		err := runfn(ctx)
		wg.Done()
		if donefn != nil {
			donefn(err)
		}
	}()
}

func StartGroup(ctx context.Context, ownerwg *sync.WaitGroup, runfns []RunFunc, donefn DoneFunc) {

	log.Debug().Msg("Start group")
	ctx, cn := context.WithCancel(ctx)

	sz := len(runfns)

	ech := make(chan error, sz)

	if ownerwg != nil {
		ownerwg.Add(1)
	}

	var wg sync.WaitGroup
	for _, runfn := range runfns {
		Start(ctx, &wg, runfn, func(er error) {
			if er != nil {
				select {
				case ech <- er:
				default:
				}
			}
		})
	}

	go func() {
		var err error
		select {
		case er := <-ech:
			err = er
		case <-ctx.Done():
		}
		cn()
		wg.Wait()
		ownerwg.Done()
		log.Debug().Msg("Group is stopped")

		if donefn != nil {
			donefn(err)
		}
	}()
}

func LoggedRunFunc(tag string, runfn RunFunc) RunFunc {
	return func(ctx context.Context) error {
		log.Debug().Msg(tag + " started")
		err := runfn(ctx)
		var ev *zerolog.Event
		if err != nil {
			log.Error().Err(err)
		}
		ev = log.Debug()
		ev.Msg(tag + " exited")
		return err
	}
}
