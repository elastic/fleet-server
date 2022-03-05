// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/status"
)

// DefaultCheckTime is the default interval for self to check for its policy.
const DefaultCheckTime = 5 * time.Second

type enrollmentTokenFetcher func(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentApiKey, error)

type SelfMonitor interface {
	// Run runs the monitor.
	Run(ctx context.Context) error
	// Status gets current status of monitor.
	Status() proto.StateObserved_Status
}

type selfMonitorT struct {
	log zerolog.Logger

	mut     sync.Mutex
	fleet   config.Fleet
	bulker  bulk.Bulk
	monitor monitor.Monitor

	policyId string
	status   proto.StateObserved_Status
	reporter status.Reporter

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
func NewSelfMonitor(fleet config.Fleet, bulker bulk.Bulk, monitor monitor.Monitor, policyId string, reporter status.Reporter) SelfMonitor {
	return &selfMonitorT{
		log:              log.With().Str("ctx", "policy self monitor").Logger(),
		fleet:            fleet,
		bulker:           bulker,
		monitor:          monitor,
		policyId:         policyId,
		status:           proto.StateObserved_STARTING,
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
			status, err := m.process(ctx)
			if err != nil {
				return err
			}
			cT.Reset(m.checkTime)
			if status == proto.StateObserved_HEALTHY {
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
			status, err := m.processPolicies(ctx, policies)
			if err != nil {
				return err
			}
			if status == proto.StateObserved_HEALTHY {
				// running; can stop
				break LOOP
			}
		}
	}

	return nil
}

func (m *selfMonitorT) Status() proto.StateObserved_Status {
	m.mut.Lock()
	defer m.mut.Unlock()
	return m.status
}

func (m *selfMonitorT) waitStart(ctx context.Context) (err error) {
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-m.startCh:
	}
	return
}

func (m *selfMonitorT) process(ctx context.Context) (proto.StateObserved_Status, error) {
	policies, err := m.policyF(ctx, m.bulker, dl.WithIndexName(m.policiesIndex))
	if err != nil {
		if !errors.Is(err, es.ErrIndexNotFound) {
			return proto.StateObserved_FAILED, nil
		}
		m.log.Debug().Str("index", m.policiesIndex).Msg(es.ErrIndexNotFound.Error())
	}
	if len(policies) == 0 {
		return m.updateStatus(ctx)
	}
	return m.processPolicies(ctx, policies)
}

func (m *selfMonitorT) processPolicies(ctx context.Context, policies []model.Policy) (proto.StateObserved_Status, error) {
	if len(policies) == 0 {
		// nothing to do
		return proto.StateObserved_STARTING, nil
	}
	latest := m.groupByLatest(policies)
	for _, policy := range latest {
		if m.policyId != "" && policy.PolicyId == m.policyId {
			m.policy = &policy
			break
		} else if m.policyId == "" && policy.DefaultFleetServer {
			m.policy = &policy
			break
		}
	}
	return m.updateStatus(ctx)
}

func (m *selfMonitorT) groupByLatest(policies []model.Policy) map[string]model.Policy {
	latest := make(map[string]model.Policy)
	for _, policy := range policies {
		curr, ok := latest[policy.PolicyId]
		if !ok {
			latest[policy.PolicyId] = policy
			continue
		}
		if policy.RevisionIdx > curr.RevisionIdx {
			latest[policy.PolicyId] = policy
			continue
		} else if policy.RevisionIdx == curr.RevisionIdx && policy.CoordinatorIdx > curr.CoordinatorIdx {
			latest[policy.PolicyId] = policy
		}
	}
	return latest
}

func (m *selfMonitorT) updateStatus(ctx context.Context) (proto.StateObserved_Status, error) {
	m.mut.Lock()
	defer m.mut.Unlock()

	if m.policy == nil {
		// no policy found
		m.status = proto.StateObserved_STARTING
		if m.policyId == "" {
			err := m.reporter.Status(proto.StateObserved_STARTING, "Waiting on default policy with Fleet Server integration", nil)
			if err != nil {
				log.Error().Err(err).Msg("Fleet server could not report 'STARTING' state to Agent")
			}
		} else {
			err := m.reporter.Status(proto.StateObserved_STARTING, fmt.Sprintf("Waiting on policy with Fleet Server integration: %s", m.policyId), nil)
			if err != nil {
				log.Error().Err(err).Msg("Fleet server could not report 'STARTING' state to Agent")
			}
		}
		return proto.StateObserved_STARTING, nil
	}

	var data policyData
	err := json.Unmarshal(m.policy.Data, &data)
	if err != nil {
		return proto.StateObserved_FAILED, err
	}
	if !data.HasType("fleet-server") {
		// no fleet-server input
		m.status = proto.StateObserved_STARTING
		if m.policyId == "" {
			err := m.reporter.Status(proto.StateObserved_STARTING, "Waiting on fleet-server input to be added to default policy", nil)
			if err != nil {
				log.Error().Err(err).Msg("Fleet server could not report 'STARTING' state to Agent")
			}
		} else {
			err := m.reporter.Status(proto.StateObserved_STARTING, fmt.Sprintf("Waiting on fleet-server input to be added to policy: %s", m.policyId), nil)
			if err != nil {
				log.Error().Err(err).Msg("Fleet server could not report 'STARTING' state to Agent")
			}
		}
		return proto.StateObserved_STARTING, nil
	}

	status := proto.StateObserved_HEALTHY
	extendMsg := ""
	var payload map[string]interface{}
	if m.fleet.Agent.ID == "" {
		status = proto.StateObserved_DEGRADED
		extendMsg = "; missing config fleet.agent.id (expected during bootstrap process)"

		// Elastic Agent has not been enrolled; Fleet Server passes back the enrollment token so the Elastic Agent
		// can perform enrollment.
		tokens, err := m.enrollmentTokenF(ctx, m.bulker, m.policy.PolicyId)
		if err != nil {
			return proto.StateObserved_FAILED, err
		}
		tokens = filterActiveTokens(tokens)
		if len(tokens) == 0 {
			// no tokens created for the policy, still starting
			if m.policyId == "" {
				err := m.reporter.Status(proto.StateObserved_STARTING, "Waiting on active enrollment keys to be created in default policy with Fleet Server integration", nil)
				if err != nil {
					log.Error().Err(err).Msg("Fleet server could not report 'STARTING' state to Agent")
				}
			} else {
				err := m.reporter.Status(proto.StateObserved_STARTING, fmt.Sprintf("Waiting on active enrollment keys to be created in policy with Fleet Server integration: %s", m.policyId), nil)
				if err != nil {
					log.Error().Err(err).Msg("Fleet server could not report 'STARTING' state to Agent")
				}
			}
			return proto.StateObserved_STARTING, nil
		}
		payload = map[string]interface{}{
			"enrollment_token": tokens[0].ApiKey,
		}
	}
	m.status = status
	if m.policyId == "" {
		err := m.reporter.Status(status, fmt.Sprintf("Running on default policy with Fleet Server integration%s", extendMsg), payload)
		if err != nil {
			log.Error().Err(err).Msgf("Fleet server could not report '%s' state to Agent", status)
		}
	} else {
		err := m.reporter.Status(status, fmt.Sprintf("Running on policy with Fleet Server integration: %s%s", m.policyId, extendMsg), payload)
		if err != nil {
			log.Error().Err(err).Msgf("Fleet server could not report '%s' state to Agent", status)
		}
	}
	return status, nil
}

type policyData struct {
	Inputs []policyInput `json:"inputs"`
}

type policyInput struct {
	Type string `json:"type"`
}

func (d *policyData) HasType(val string) bool {
	for _, input := range d.Inputs {
		if input.Type == val {
			return true
		}
	}
	return false
}

func findEnrollmentAPIKeys(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentApiKey, error) {
	return dl.FindEnrollmentAPIKeys(ctx, bulker, dl.QueryEnrollmentAPIKeyByPolicyID, dl.FieldPolicyId, policyID)
}

func filterActiveTokens(tokens []model.EnrollmentApiKey) []model.EnrollmentApiKey {
	active := make([]model.EnrollmentApiKey, 0, len(tokens))
	for _, t := range tokens {
		if t.Active {
			active = append(active, t)
		}
	}
	return active
}
