// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type standAloneSelfMonitorT struct {
	log zerolog.Logger

	mut   sync.RWMutex
	state client.UnitState

	bulker   bulk.Bulk
	reporter state.Reporter

	policyF       policyFetcher
	policiesIndex string
	checkTime     time.Duration
}

// NewStandAloneSelfMonitor creates the self policy monitor for an stand-alone Fleet Server.
//
// Checks that this Fleet Server has access to the policies index.
func NewStandAloneSelfMonitor(bulker bulk.Bulk, reporter state.Reporter) *standAloneSelfMonitorT {
	return &standAloneSelfMonitorT{
		log:           log.With().Str("ctx", "policy self monitor").Logger(),
		bulker:        bulker,
		state:         client.UnitStateStarting,
		reporter:      reporter,
		policyF:       dl.QueryLatestPolicies,
		policiesIndex: dl.FleetPolicies,
		checkTime:     DefaultCheckTime,
	}
}

// Run runs the monitor.
func (m *standAloneSelfMonitorT) Run(ctx context.Context) error {
	cT := time.NewTicker(m.checkTime)
	defer cT.Stop()

	for {
		state := m.check(ctx)
		if state == client.UnitStateHealthy {
			// running; can stop
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-cT.C:
		}
	}

	return nil
}

func (m *standAloneSelfMonitorT) updateState(state client.UnitState, reason string) client.UnitState {
	m.mut.Lock()
	defer m.mut.Unlock()

	if m.state != state {
		m.reporter.UpdateState(state, reason, nil)
		m.state = state
	}

	return state
}

func (m *standAloneSelfMonitorT) State() client.UnitState {
	m.mut.RLock()
	defer m.mut.RUnlock()
	return m.state
}

func (m *standAloneSelfMonitorT) Policy() *model.Policy {
	return nil
}

func (m *standAloneSelfMonitorT) check(ctx context.Context) client.UnitState {
	_, err := m.policyF(ctx, m.bulker, dl.WithIndexName(m.policiesIndex))
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			m.log.Debug().Str("index", m.policiesIndex).Msg(es.ErrIndexNotFound.Error())
			return m.updateState(client.UnitStateStarting, "Policies not available yet")
		}
		if err != nil {
			return m.updateState(client.UnitStateFailed, fmt.Sprintf("Failed to request policies: %s", err))
		}
	}

	return m.updateState(client.UnitStateHealthy, "Running")
}
