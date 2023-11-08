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
	"go.elastic.co/apm/v2"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
)

// DefaultCheckTime is the default interval for self to check for its policy.
const DefaultCheckTime = 5 * time.Second

// DefaultCheckTimeout is the default timeout when checking for policies.
const DefaultCheckTimeout = 30 * time.Second

type enrollmentTokenFetcher func(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentAPIKey, error)

type SelfMonitor interface {
	// Run runs the monitor.
	Run(ctx context.Context) error
	// State gets current state of monitor.
	State() client.UnitState
}

type selfMonitorT struct {
	log zerolog.Logger

	mut     sync.Mutex
	fleet   config.Fleet
	bulker  bulk.Bulk
	monitor monitor.Monitor

	policyID string
	state    client.UnitState
	reporter state.Reporter

	policy *model.Policy

	policyF          policyFetcher
	policiesIndex    string
	enrollmentTokenF enrollmentTokenFetcher
	checkTime        time.Duration

	startCh chan struct{}
}

// NewSelfMonitor creates the self policy monitor.
//
// Ensures that the policy that this Fleet Server attached to exists and that it
// has a Fleet Server input defined.
func NewSelfMonitor(fleet config.Fleet, bulker bulk.Bulk, monitor monitor.Monitor, policyID string, reporter state.Reporter) SelfMonitor {
	return &selfMonitorT{
		fleet:            fleet,
		bulker:           bulker,
		monitor:          monitor,
		policyID:         policyID,
		state:            client.UnitStateStarting,
		reporter:         reporter,
		policyF:          dl.QueryLatestPolicies,
		policiesIndex:    dl.FleetPolicies,
		enrollmentTokenF: findEnrollmentAPIKeys,
		checkTime:        DefaultCheckTime,
		startCh:          make(chan struct{}),
	}
}

// Run runs the monitor.
func (m *selfMonitorT) Run(ctx context.Context) error {
	m.log = zerolog.Ctx(ctx).With().Str("ctx", "policy self monitor").Logger()
	s := m.monitor.Subscribe()
	defer m.monitor.Unsubscribe(s)

	_, err := m.process(ctx)
	if err != nil {
		return err
	}

	cT := time.NewTimer(m.checkTime)
	defer cT.Stop()

	close(m.startCh)

LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case <-cT.C:
			state, err := m.process(ctx)
			if err != nil {
				return err
			}
			cT.Reset(m.checkTime)
			if state == client.UnitStateHealthy {
				// running; can stop
				break LOOP
			}
		case hits := <-s.Output():
			policies := make([]model.Policy, len(hits))
			for i, hit := range hits {
				err := hit.Unmarshal(&policies[i])
				if err != nil {
					return err
				}
			}
			state, err := m.processPolicies(ctx, policies)
			if err != nil {
				return err
			}
			if state == client.UnitStateHealthy {
				// running; can stop
				break LOOP
			}
		}
	}

	return nil
}

func (m *selfMonitorT) State() client.UnitState {
	m.mut.Lock()
	defer m.mut.Unlock()
	return m.state
}

func (m *selfMonitorT) waitStart(ctx context.Context) error { //nolint:unused // not sure if this is used in tests
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.startCh:
	}
	return nil
}

func (m *selfMonitorT) process(ctx context.Context) (client.UnitState, error) {
	if m.bulker.HasTracer() {
		trans := m.bulker.StartTransaction("Check self monitor", "bulker")
		ctx = apm.ContextWithTransaction(ctx, trans)
		defer trans.End()
	}
	policies, err := m.policyF(ctx, m.bulker, dl.WithIndexName(m.policiesIndex))
	if err != nil {
		if !errors.Is(err, es.ErrIndexNotFound) {
			return client.UnitStateFailed, nil
		}
		m.log.Debug().Str("index", m.policiesIndex).Msg(es.ErrIndexNotFound.Error())
	}
	if len(policies) == 0 {
		return m.updateState(ctx)
	}
	return m.processPolicies(ctx, policies)
}

func (m *selfMonitorT) processPolicies(ctx context.Context, policies []model.Policy) (client.UnitState, error) {
	if len(policies) == 0 {
		// nothing to do
		return client.UnitStateStarting, nil
	}
	latest := m.groupByLatest(policies)
	for i := range latest {
		policy := latest[i]
		if m.policyID != "" && policy.PolicyID == m.policyID {
			m.policy = &policy
			break
		} else if m.policyID == "" && policy.DefaultFleetServer {
			m.policy = &policy
			break
		}
	}
	return m.updateState(ctx)
}

func (m *selfMonitorT) groupByLatest(policies []model.Policy) map[string]model.Policy {
	return groupByLatest(policies)
}

func (m *selfMonitorT) updateState(ctx context.Context) (client.UnitState, error) {
	m.mut.Lock()
	defer m.mut.Unlock()

	if m.policy == nil {
		// no policy found
		m.state = client.UnitStateStarting
		if m.policyID == "" {
			m.reporter.UpdateState(client.UnitStateStarting, "Waiting on default policy with Fleet Server integration", nil) //nolint:errcheck // not clear what to do in failure cases
		} else {
			m.reporter.UpdateState(client.UnitStateStarting, fmt.Sprintf("Waiting on policy with Fleet Server integration: %s", m.policyID), nil) //nolint:errcheck // not clear what to do in failure cases
		}
		return client.UnitStateStarting, nil
	}

	if !HasFleetServerInput(m.policy.Data.Inputs) {
		// no fleet-server input
		m.state = client.UnitStateStarting
		if m.policyID == "" {
			m.reporter.UpdateState(client.UnitStateStarting, "Waiting on fleet-server input to be added to default policy", nil) //nolint:errcheck // not clear what to do in failure cases
		} else {
			m.reporter.UpdateState(client.UnitStateStarting, fmt.Sprintf("Waiting on fleet-server input to be added to policy: %s", m.policyID), nil) //nolint:errcheck // not clear what to do in failure cases
		}
		return client.UnitStateStarting, nil
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
		m.state = client.UnitStateDegraded
		m.reporter.UpdateState(client.UnitStateDegraded, "Could not connect to remote ES output", remoteESPayload) //nolint:errcheck // not clear what to do in failure cases
		return client.UnitStateDegraded, nil
	}

	state := client.UnitStateHealthy
	extendMsg := ""
	var payload map[string]interface{}
	if m.fleet.Agent.ID == "" {
		state = client.UnitStateDegraded
		extendMsg = "; missing config fleet.agent.id (expected during bootstrap process)"

		// Elastic Agent has not been enrolled; Fleet Server passes back the enrollment token so the Elastic Agent
		// can perform enrollment.
		tokens, err := m.enrollmentTokenF(ctx, m.bulker, m.policy.PolicyID)
		if err != nil {
			return client.UnitStateFailed, err
		}
		if len(tokens) == 0 {
			// no tokens created for the policy, still starting
			if m.policyID == "" {
				m.reporter.UpdateState(client.UnitStateStarting, "Waiting on active enrollment keys to be created in default policy with Fleet Server integration", nil) //nolint:errcheck // not clear what to do in failure cases
			} else {
				m.reporter.UpdateState(client.UnitStateStarting, fmt.Sprintf("Waiting on active enrollment keys to be created in policy with Fleet Server integration: %s", m.policyID), nil) //nolint:errcheck // not clear what to do in failure cases
			}
			return client.UnitStateStarting, nil
		}
		payload = map[string]interface{}{
			"enrollment_token": tokens[0].APIKey,
		}
	}
	m.state = state
	if m.policyID == "" {
		m.reporter.UpdateState(state, fmt.Sprintf("Running on default policy with Fleet Server integration%s", extendMsg), payload) //nolint:errcheck // not clear what to do in failure cases
	} else {
		m.reporter.UpdateState(state, fmt.Sprintf("Running on policy with Fleet Server integration: %s%s", m.policyID, extendMsg), payload) //nolint:errcheck // not clear what to do in failure cases
	}
	return state, nil
}

func HasFleetServerInput(inputs []map[string]interface{}) bool {
	for _, input := range inputs {
		attr, ok := input["type"].(string)
		if !ok {
			return false
		}
		if attr == "fleet-server" {
			return true
		}
	}
	return false
}

func findEnrollmentAPIKeys(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentAPIKey, error) {
	return dl.FindEnrollmentAPIKeys(ctx, bulker, dl.QueryEnrollmentAPIKeyByPolicyID, dl.FieldPolicyID, policyID)
}
