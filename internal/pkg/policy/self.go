// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"net/http"
	"sync"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/status"
)

type SelfMonitor interface {
	// Run runs the monitor.
	Run(ctx context.Context) error
}

type selfMonitorT struct {
	log zerolog.Logger

	mut     sync.Mutex
	fleet   config.Fleet
	bulker  bulk.Bulk
	monitor monitor.Monitor

	policyId string
	reporter status.Reporter

	policy *model.Policy

	policyF       policyFetcher
	policiesIndex string
}

// NewSelfMonitor creates the self policy monitor.
//
// Ensures that the policy that this Fleet Server attached to exists and that it
// has a Fleet Server input defined.
func NewSelfMonitor(fleet config.Fleet, bulker bulk.Bulk, monitor monitor.Monitor, policyId string, reporter status.Reporter) SelfMonitor {
	return &selfMonitorT{
		log:           log.With().Str("ctx", "policy self monitor").Logger(),
		fleet:         fleet,
		bulker:        bulker,
		monitor:       monitor,
		policyId:      policyId,
		reporter:      reporter,
		policyF:       dl.QueryLatestPolicies,
		policiesIndex: dl.FleetPolicies,
	}
}

// Run runs the monitor.
func (m *selfMonitorT) Run(ctx context.Context) error {
	s := m.monitor.Subscribe()
	defer m.monitor.Unsubscribe(s)

	err := m.process(ctx)
	if err != nil {
		return err
	}

LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case hits := <-s.Output():
			policies := make([]model.Policy, len(hits))
			for i, hit := range hits {
				err := hit.Unmarshal(&policies[i])
				if err != nil {
					return err
				}
			}
			if err := m.processPolicies(ctx, policies); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *selfMonitorT) process(ctx context.Context) error {
	policies, err := m.policyF(ctx, m.bulker, dl.WithIndexName(m.policiesIndex))
	if err != nil {
		elasticErr, ok := err.(*es.ErrElastic)
		if !ok {
			return err
		}
		if elasticErr.Status != http.StatusNotFound {
			return err
		}
	}
	if len(policies) == 0 {
		m.updateStatus()
		return nil
	}
	return m.processPolicies(ctx, policies)
}

func (m *selfMonitorT) processPolicies(ctx context.Context, policies []model.Policy) error {
	if len(policies) == 0 {
		// nothing to do
		return nil
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
	return m.updateStatus()
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

func (m *selfMonitorT) updateStatus() error {
	if m.policy == nil {
		// no policy found
		if m.policyId == "" {
			m.reporter.Status(proto.StateObserved_STARTING, "Waiting on default policy with Fleet Server integration", nil)
		} else {
			m.reporter.Status(proto.StateObserved_STARTING, fmt.Sprintf("Waiting on policy with Fleet Server integration: %s", m.policyId), nil)
		}
		return nil
	}

	var data policyData
	err := json.Unmarshal(m.policy.Data, &data)
	if err != nil {
		return err
	}
	if !data.HasType("fleet-server") {
		return errors.New("assigned policy does not have fleet-server input")
	}

	status := proto.StateObserved_HEALTHY
	extendMsg := ""
	if m.fleet.Agent.ID == "" {
		status = proto.StateObserved_DEGRADED
		extendMsg = "; missing config fleet.agent.id"
	}
	if m.policyId == "" {
		m.reporter.Status(status, fmt.Sprintf("Running on default policy with Fleet Server integration%s", extendMsg), nil)
	} else {
		m.reporter.Status(status, fmt.Sprintf("Running on policy with Fleet Server integration: %s%s", m.policyId, extendMsg), nil)
	}
	return nil
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
