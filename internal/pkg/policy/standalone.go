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
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"
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
	checkTimeout  time.Duration
}

// NewStandAloneSelfMonitor creates the self policy monitor for an stand-alone Fleet Server.
//
// Checks that this Fleet Server has access to the policies index.
func NewStandAloneSelfMonitor(bulker bulk.Bulk, reporter state.Reporter) *standAloneSelfMonitorT {
	return &standAloneSelfMonitorT{
		bulker:        bulker,
		state:         client.UnitStateStarting,
		reporter:      reporter,
		policyF:       dl.QueryLatestPolicies,
		policiesIndex: dl.FleetPolicies,
		checkTime:     DefaultCheckTime,
		checkTimeout:  DefaultCheckTimeout,
	}
}

// Run runs the monitor.
func (m *standAloneSelfMonitorT) Run(ctx context.Context) error {
	m.log = zerolog.Ctx(ctx).With().Str("ctx", "policy self monitor").Logger()
	ticker := time.NewTicker(m.checkTime)
	defer ticker.Stop()

	for {
		m.check(ctx)

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (m *standAloneSelfMonitorT) updateState(state client.UnitState, reason string) {
	m.mut.Lock()
	defer m.mut.Unlock()

	m.reporter.UpdateState(state, reason, nil) //nolint:errcheck // not clear what to do in failure cases
	m.state = state
}

func (m *standAloneSelfMonitorT) State() client.UnitState {
	m.mut.RLock()
	defer m.mut.RUnlock()
	return m.state
}

func (m *standAloneSelfMonitorT) check(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, m.checkTimeout)
	defer cancel()

	if m.bulker.HasTracer() {
		trans := m.bulker.StartTransaction("Check standalone", "bulker")
		ctx = apm.ContextWithTransaction(ctx, trans)
		defer trans.End()
	}

	current := m.State()
	state := client.UnitStateHealthy
	message := "Running"

	_, err := m.policyF(ctx, m.bulker, dl.WithIndexName(m.policiesIndex))
	if errors.Is(err, es.ErrIndexNotFound) {
		m.log.Debug().Str("index", m.policiesIndex).Msg(es.ErrIndexNotFound.Error())
		message = "Running: Policies not available yet"
	} else if err != nil {
		switch current {
		case client.UnitStateHealthy, client.UnitStateDegraded:
			state = client.UnitStateDegraded
		case client.UnitStateStarting:
			state = client.UnitStateStarting
		default:
			state = client.UnitStateFailed
		}

		message = fmt.Sprintf("Failed to request policies: %s", err)
	}

	remoteOutputErrorMap := m.bulker.GetRemoteOutputErrorMap()
	hasError := false
	remoteESPayload := make(map[string]interface{})
	for key, value := range remoteOutputErrorMap {
		if value != "" {
			hasError = true
			remoteESPayload[key] = value
		}
	}
	if hasError {
		state = client.UnitStateDegraded
		message = fmt.Sprintf("Could not connect to remote ES output: %+v", remoteESPayload)
	}

	if current != state {
		m.updateState(state, message)
	}
}
