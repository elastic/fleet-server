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

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/reload"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/go-ucfg"
	"github.com/rs/zerolog/log"
)

const (
	kAgentModeRestartLoopDelay = 2 * time.Second

	kFleetServer   = "fleet-server"
	kElasticsearch = "elasticsearch"

	kStopped = "Stopped"
)

type clientUnit interface {
	Expected() (client.UnitState, client.UnitLogLevel, *proto.UnitExpectedConfig)
	UpdateState(state client.UnitState, message string, payload map[string]interface{}) error
}

// Agent is a fleet-server that runs under the elastic-agent.
// An Agent instance will retrieve connection information from the passed reader (normally stdin).
// Agent uses client.StateInterface to gather config data and manage its lifecylce.
type Agent struct {
	cliCfg      *ucfg.Config
	bi          build.Info
	reloadables []reload.Reloadable

	agent client.V2

	outputUnit clientUnit
	inputUnit  clientUnit

	srv          *Fleet
	srvCtx       context.Context
	srvCanceller context.CancelFunc
	srvDone      chan bool
}

// NewAgent returns an Agent that will gather connection information from the passed reader.
func NewAgent(cliCfg *ucfg.Config, reader io.Reader, bi build.Info, reloadables ...reload.Reloadable) (*Agent, error) {
	var err error

	a := &Agent{
		cliCfg:      cliCfg,
		bi:          bi,
		reloadables: reloadables,
	}
	a.agent, _, err = client.NewV2FromReader(reader, client.VersionInfo{
		Name:    kFleetServer,
		Version: bi.Version,
		Meta: map[string]string{
			"commit":     bi.Commit,
			"build_time": bi.BuildTime.String(),
		},
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Run starts a Server instance using config from the configured client.
func (a *Agent) Run(ctx context.Context) error {
	subCtx, subCanceller := context.WithCancel(ctx)
	defer subCanceller()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-subCtx.Done():
				return
			case err := <-a.agent.Errors():
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
					log.Error().Err(err)
				}
			case change := <-a.agent.UnitChanges():
				switch change.Type {
				case client.UnitChangedAdded:
					err := a.unitAdded(subCtx, change.Unit)
					if err != nil {
						log.Error().Str("unit", change.Unit.ID()).Err(err)
						_ = change.Unit.UpdateState(client.UnitStateFailed, err.Error(), nil)
					}
				case client.UnitChangedModified:
					err := a.unitModified(subCtx, change.Unit)
					if err != nil {
						log.Error().Str("unit", change.Unit.ID()).Err(err)
						_ = change.Unit.UpdateState(client.UnitStateFailed, err.Error(), nil)
					}
				case client.UnitChangedRemoved:
					a.unitRemoved(change.Unit)
				}
			case <-t.C:
				// Fleet Server is the only component that gets started by Elastic Agent without an Agent ID. We loop
				// here on interval waiting for the Elastic Agent to enroll so then the Agent ID is then set.
				agentInfo := a.agent.AgentInfo()
				if agentInfo != nil && agentInfo.ID != "" {
					// Agent ID is not set for the component.
					t.Stop()
					err := a.reconfigure(subCtx)
					if err != nil {
						log.Error().Err(err)
					}
				}
			}
		}
	}()

	log.Info().Msg("starting communication connection back to Elastic Agent")
	err := a.agent.Start(subCtx)
	if err != nil {
		return err
	}

	<-subCtx.Done()
	wg.Wait()

	return nil
}

// UpdateState updates the state of the message and payload.
func (a *Agent) UpdateState(state client.UnitState, message string, payload map[string]interface{}) error {
	if a.inputUnit != nil {
		_ = a.inputUnit.UpdateState(state, message, payload)
	}
	if a.outputUnit != nil {
		_ = a.outputUnit.UpdateState(state, message, payload)
	}
	return nil
}

func (a *Agent) unitAdded(ctx context.Context, unit *client.Unit) error {
	if unit.Type() == client.UnitTypeInput {
		_, _, cfg := unit.Expected()
		if cfg.Type != kFleetServer {
			// not support input type
			_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("%s is an unsupported input type", cfg.Type), nil)
			return nil
		}
		if a.inputUnit != nil {
			// original input unit is being stopped; swapping in this unit as the new input unit
			_ = a.inputUnit.UpdateState(client.UnitStateStopped, kStopped, nil)
		}
		a.inputUnit = unit
		if a.outputUnit == nil {
			// waiting for output unit to really start Fleet Server
			_ = unit.UpdateState(client.UnitStateStarting, "waiting for output unit", nil)
			return nil
		}
		return a.start(ctx)
	}
	if unit.Type() == client.UnitTypeOutput {
		_, _, cfg := unit.Expected()
		if cfg.Type != kElasticsearch {
			// not support output type
			_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("%s is an unsupported output type", cfg.Type), nil)
			return nil
		}
		if a.outputUnit != nil {
			// original output unit is being stopped; swapping in this unit as the new output unit
			_ = a.outputUnit.UpdateState(client.UnitStateStopped, kStopped, nil)
		}
		a.outputUnit = unit
		if a.inputUnit == nil {
			// waiting for input unit to really start Fleet Server
			_ = unit.UpdateState(client.UnitStateStarting, "waiting for input unit", nil)
			return nil
		}
		return a.start(ctx)
	}
	return fmt.Errorf("unknown unit type %v", unit.Type())
}

func (a *Agent) unitModified(ctx context.Context, unit *client.Unit) error {
	state, _, _ := unit.Expected()
	if unit.Type() == client.UnitTypeInput {
		if a.inputUnit != unit {
			// not our input unit; would have been marked failed in unitAdded; do nothing
			return nil
		}
		if state == client.UnitStateHealthy {
			if a.outputUnit == nil {
				// still no output unit; would have been marked starting already; do nothing
				return nil
			}

			// configuration modified (should still be running)
			return a.reconfigure(ctx)
		} else if state == client.UnitStateStopped {
			// unit should be stopped
			a.stop()
			return nil
		}
		return fmt.Errorf("unknown unit state %v", state)
	}
	if unit.Type() == client.UnitTypeOutput {
		if a.outputUnit != unit {
			// not our output unit; would have been marked failed in unitAdded; do nothing
			return nil
		}
		if state == client.UnitStateHealthy {
			if a.inputUnit == nil {
				// still no input unit; would have been marked starting already; do nothing
				return nil
			}

			// configuration modified (should still be running)
			return a.reconfigure(ctx)
		} else if state == client.UnitStateStopped {
			// unit should be stopped
			a.stop()
			return nil
		}
		return fmt.Errorf("unknown unit state %v", state)
	}
	return fmt.Errorf("unknown unit type %v", unit.Type())
}

func (a *Agent) unitRemoved(unit *client.Unit) {
	stop := false
	if a.inputUnit == unit || a.outputUnit == unit {
		stop = true
	}
	if stop {
		a.stop()
	}
	if a.inputUnit == unit {
		a.inputUnit = nil
	}
	if a.outputUnit == unit {
		a.outputUnit = nil
	}
}

func (a *Agent) start(ctx context.Context) error {
	if a.srv != nil {
		return a.reconfigure(ctx)
	}

	cfg, err := a.configFromUnits()
	if err != nil {
		return err
	}

	// reload the generic reloadables
	for _, r := range a.reloadables {
		err = r.Reload(ctx, cfg)
		if err != nil {
			return err
		}
	}

	srvDone := make(chan bool)
	srvCtx, srvCanceller := context.WithCancel(ctx)
	srv, err := NewFleet(a.bi, state.NewChained(state.NewLog(), a), false)
	if err != nil {
		close(srvDone)
		srvCanceller()
		return err
	}

	go func() {
		defer close(srvDone)
		for {
			err := srv.Run(srvCtx, cfg)
			if err == nil || errors.Is(err, context.Canceled) {
				return
			}
			// sleep some before calling Run again
			_ = sleep.WithContext(srvCtx, kAgentModeRestartLoopDelay)
		}
	}()

	a.srv = srv
	a.srvCtx = srvCtx
	a.srvCanceller = srvCanceller
	a.srvDone = srvDone
	return nil
}

func (a *Agent) reconfigure(ctx context.Context) error {
	if a.srv == nil {
		return a.start(ctx)
	}

	cfg, err := a.configFromUnits()
	if err != nil {
		return err
	}

	// reload the generic reloadables
	for _, r := range a.reloadables {
		err = r.Reload(ctx, cfg)
		if err != nil {
			return err
		}
	}

	return a.srv.Reload(ctx, cfg)
}

func (a *Agent) stop() {
	if a.srvCanceller == nil {
		return
	}

	canceller := a.srvCanceller
	a.srvCanceller = nil
	a.srvCtx = nil
	a.srv = nil
	canceller()
	<-a.srvDone
	a.srvDone = nil

	if a.inputUnit != nil {
		_ = a.inputUnit.UpdateState(client.UnitStateStopped, kStopped, nil)
	}
	if a.outputUnit != nil {
		_ = a.outputUnit.UpdateState(client.UnitStateStopped, kStopped, nil)
	}
}

// configFromUnits takes both inputUnit and outputUnit and creates a single configuration just like fleet server was
// being started from a configuration file.
func (a *Agent) configFromUnits() (*config.Config, error) {
	agentID := ""
	agentVersion := ""
	agentInfo := a.agent.AgentInfo()
	if agentInfo != nil {
		agentID = agentInfo.ID
		agentVersion = agentInfo.Version
	}
	_, inputLevel, inputCfg := a.inputUnit.Expected()
	_, outputLevel, outputCfg := a.outputUnit.Expected()
	logLevel := inputLevel
	if outputLevel > logLevel {
		logLevel = outputLevel
	}

	// pass inputs from policy through go-ucfg in order to flatten keys
	// if inputCfg.Source.AsMap() is passed directly, any additional server.* settings will be missed
	var input map[string]interface{}
	inputsConfig, err := ucfg.NewFrom(inputCfg.Source.AsMap(), config.DefaultOptions...)
	if err != nil {
		return nil, err
	}
	if err := inputsConfig.Unpack(&input, config.DefaultOptions...); err != nil {
		return nil, err
	}

	cfgData, err := ucfg.NewFrom(map[string]interface{}{
		"fleet": map[string]interface{}{
			"agent": map[string]interface{}{
				"id":      agentID,
				"version": agentVersion,
				"logging": map[string]interface{}{
					"level": logLevel.String(),
				},
			},
		},
		"output": map[string]interface{}{
			"elasticsearch": outputCfg.Source.AsMap(),
		},
		"inputs": []interface{}{
			input,
		},
		"logging": map[string]interface{}{
			"level": logLevel.String(),
		},
	})
	if err != nil {
		return nil, err
	}

	cliCfg := ucfg.MustNewFrom(a.cliCfg, config.DefaultOptions...)
	err = cliCfg.Merge(cfgData, config.DefaultOptions...)
	if err != nil {
		return nil, err
	}
	return config.FromConfig(cliCfg)
}
