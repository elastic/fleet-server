// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/yaml"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/reload"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/status"

	"github.com/rs/zerolog/log"
)

const kAgentModeRestartLoopDelay = 2 * time.Second

type firstCfg struct {
	cfg *config.Config
	err error
}

// Agent is a fleet-server that runs under the elastic-agent.
// An Agent instance will retrieve connection information from the passed reader (normally stdin).
// Agent uses client.StateInterface to gather config data and manage its lifecylce.
type Agent struct {
	cliCfg      *ucfg.Config
	bi          build.Info
	reloadables []reload.Reloadable

	agent client.Client

	mux          sync.Mutex
	firstCfg     chan firstCfg
	srv          *Fleet
	srvCtx       context.Context
	srvCanceller context.CancelFunc
	startChan    chan struct{}
}

// NewAgent returns an Agent that will gather connection information from the passed reader.
func NewAgent(cliCfg *ucfg.Config, reader io.Reader, bi build.Info, reloadables ...reload.Reloadable) (*Agent, error) {
	var err error

	a := &Agent{
		cliCfg:      cliCfg,
		bi:          bi,
		reloadables: reloadables,
	}
	a.agent, err = client.NewFromReader(reader, a)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Run starts a Server instance using config from the configured client.
func (a *Agent) Run(ctx context.Context) error {
	ctx, canceller := context.WithCancel(ctx)
	defer canceller()

	a.firstCfg = make(chan firstCfg)
	a.startChan = make(chan struct{}, 1)
	log.Info().Msg("starting communication connection back to Elastic Agent")
	err := a.agent.Start(ctx)
	if err != nil {
		return err
	}

	// wait for the initial configuration to be sent from the
	// Elastic Agent before starting the actual Fleet Server.
	log.Info().Msg("waiting for Elastic Agent to send initial configuration")
	var cfg firstCfg
	select {
	case <-ctx.Done():
		return fmt.Errorf("never received initial configuration: %w", ctx.Err())
	case cfg = <-a.firstCfg:
	}

	// possible that first configuration resulted in an error
	if cfg.err != nil {
		// unblock startChan even though there was an error
		a.startChan <- struct{}{}
		return cfg.err
	}

	// start fleet server with the initial configuration and its
	// own context (needed so when OnStop occurs the fleet server
	// is stopped and not the elastic-agent-client as well)
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()
	log.Info().Msg("received initial configuration starting Fleet Server")
	srv, err := NewFleet(cfg.cfg, a.bi, status.NewChained(status.NewLog(), a.agent))
	if err != nil {
		// unblock startChan even though there was an error
		a.startChan <- struct{}{}
		return err
	}
	a.mux.Lock()
	close(a.firstCfg)
	a.firstCfg = nil
	a.srv = srv
	a.srvCtx = srvCtx
	a.srvCanceller = srvCancel
	a.mux.Unlock()

	// trigger startChan so OnConfig can continue
	a.startChan <- struct{}{}

	// keep trying to restart the FleetServer on failure, reporting
	// the status back to Elastic Agent
	res := make(chan error)
	go func() {
		for {
			err := a.srv.Run(srvCtx)
			if err == nil || errors.Is(err, context.Canceled) {
				res <- err
				return
			}
			// sleep some before calling Run again
			_ = sleep.WithContext(srvCtx, kAgentModeRestartLoopDelay)
		}
	}()
	return <-res
}

// OnConfig defines what the fleet-server running under the elastic-agent does when it receives a new config.
// This is part of the client.StateInterface definition.
func (a *Agent) OnConfig(s string) {
	a.mux.Lock()
	cliCfg := ucfg.MustNewFrom(a.cliCfg, config.DefaultOptions...)
	srv := a.srv
	ctx := a.srvCtx
	canceller := a.srvCanceller
	cfgChan := a.firstCfg
	startChan := a.startChan
	a.mux.Unlock()

	var cfg *config.Config
	var err error
	defer func() {
		if err != nil {
			if cfgChan != nil {
				// failure on first config
				cfgChan <- firstCfg{
					cfg: nil,
					err: err,
				}
				// block until startChan signalled
				<-startChan
				return
			}

			log.Err(err).Msg("failed to reload configuration")
			if canceller != nil {
				canceller()
			}
		}
	}()

	// load configuration and then merge it on top of the CLI configuration
	var cfgData *ucfg.Config
	cfgData, err = yaml.NewConfig([]byte(s), config.DefaultOptions...)
	if err != nil {
		return
	}
	err = cliCfg.Merge(cfgData, config.DefaultOptions...)
	if err != nil {
		return
	}
	cfg, err = config.FromConfig(cliCfg)
	if err != nil {
		return
	}

	// Pass config if it's the initial config on startup
	// TODO maybe use sync.Once to make it clear that this block only occurs on startup?
	if cfgChan != nil {
		// reload the generic reloadables
		for _, r := range a.reloadables {
			err = r.Reload(ctx, cfg)
			if err != nil {
				return
			}
		}

		// send starting configuration so Fleet Server can start
		cfgChan <- firstCfg{
			cfg: cfg,
			err: nil,
		}

		// block handling more OnConfig calls until the Fleet Server
		// has been fully started
		<-startChan
	} else if srv != nil { // Reload config if the server is running.
		// reload the generic reloadables
		for _, r := range a.reloadables {
			err = r.Reload(ctx, cfg)
			if err != nil {
				return
			}
		}

		// reload the server
		err = srv.Reload(ctx, cfg)
		if err != nil {
			return
		}
	} else {
		err = fmt.Errorf("internal service should have been started")
		return
	}
}

// OnStop defines what the fleet-server running under the elastic-agent does when the agent sends a stop signal.
// This is part of the client.StateInterface definition.
// The root context will be cancelled to stop.
func (a *Agent) OnStop() {
	a.mux.Lock()
	canceller := a.srvCanceller
	a.mux.Unlock()

	if canceller != nil {
		canceller()
	}
}

// OnError defines what the fleet-server running under the elastic-agent does when there is an error communicating with the elastic-agent.
// This is part of the client.StateInterface definition.
// Communication errors will be logged. The elastic-agent-client handles
// retries and reconnects internally automatically.
func (a *Agent) OnError(err error) {
	log.Err(err)
}
