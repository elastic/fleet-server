// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/go-ucfg"
	"go.elastic.co/apm/v2"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
)

// DefaultCheckTime is the default interval for self to check for its policy.
const DefaultCheckTime = 5 * time.Second

// DefaultCheckTimeout is the default timeout when checking for policies.
const DefaultCheckTimeout = 30 * time.Second

var errInvalidOutput = fmt.Errorf("policy output invalid")

var ErrNoPolicyUpdate = fmt.Errorf("policy has not updated")

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
	cfgCh   chan<- *config.Config

	policyID string
	state    client.UnitState
	reporter state.Reporter

	policy  *model.Policy
	lastRev int64

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
func NewSelfMonitor(fleet config.Fleet, bulker bulk.Bulk, monitor monitor.Monitor, policyID string, reporter state.Reporter, cfgCh chan<- *config.Config) SelfMonitor {
	return &selfMonitorT{
		fleet:            fleet,
		bulker:           bulker,
		monitor:          monitor,
		cfgCh:            cfgCh,
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
			m.log.Trace().Msg(state.String())
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
			m.log.Trace().Msg(state.String())
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
			esOut, err := m.getPolicyOutput()
			if err != nil {
				if !errors.Is(err, ErrNoPolicyUpdate) {
					m.log.Warn().Err(err).Str(logger.PolicyID, m.policyID).Msg("Failed to get fleet-server output")
				}
			} else {
				m.cfgCh <- &config.Config{
					Output: config.Output{
						Elasticsearch: esOut,
					},
					RevisionIdx: m.lastRev,
				}
			}
			break
		} else if m.policyID == "" && policy.DefaultFleetServer {
			m.policy = &policy
			esOut, err := m.getPolicyOutput()
			if err != nil {
				if !errors.Is(err, ErrNoPolicyUpdate) {
					m.log.Warn().Err(err).Str(logger.PolicyID, m.policyID).Msg("Failed to get fleet-server output")
				}
			} else {
				m.cfgCh <- &config.Config{
					Output: config.Output{
						Elasticsearch: esOut,
					},
					RevisionIdx: m.lastRev,
				}
			}
			break
		}
	}
	return m.updateState(ctx)
}

func (m *selfMonitorT) groupByLatest(policies []model.Policy) map[string]model.Policy {
	return groupByLatest(policies)
}

// getPolicyOutput will return the Elasticsearch output block of m.policy if there is a new revision.
func (m *selfMonitorT) getPolicyOutput() (config.Elasticsearch, error) {
	var policyES config.Elasticsearch
	// policy revision has not changed
	if m.policy.RevisionIdx == m.lastRev {
		return policyES, ErrNoPolicyUpdate
	}
	// always copy revisionIdx
	m.lastRev = m.policy.RevisionIdx

	// Find elasticsearch output in the policy
	// TODO figure out how to get output name from policy in order not to scan outputs?
	for name, data := range m.policy.Data.Outputs {
		outType, ok := data["type"].(string)
		if !ok {
			return policyES, fmt.Errorf("output name %s has non-string in type attribute: %w", name, errInvalidOutput)
		}
		if outType == OutputTypeElasticsearch {
			output, err := ucfg.NewFrom(data, config.DefaultOptions...)
			if err != nil {
				return policyES, fmt.Errorf("unable to create config from output data: %w", err)
			}
			if err := output.Unpack(&policyES, config.DefaultOptions...); err != nil {
				return policyES, fmt.Errorf("unable to unback config data to config.Elasticsearch: %w", err)
			}
			break
		}
	}

	// The output block in the policy may not have the schema set so we need to manually set it.
	isHTTPS := false
	for _, host := range policyES.Hosts {
		if strings.HasPrefix(strings.ToLower(host), "https") {
			isHTTPS = true
			break
		}
	}
	if isHTTPS {
		policyES.Protocol = "https"
	}
	return policyES, nil
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

	reportOutputHealth(ctx, m.bulker, m.log)

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

func isOutputCfgOutdated(ctx context.Context, bulker bulk.Bulk, zlog zerolog.Logger, outputName string) bool {
	policy, err := dl.QueryOutputFromPolicy(ctx, bulker, outputName)
	if err != nil || policy == nil {
		return true
	}
	hasChanged := bulker.RemoteOutputConfigChanged(zlog, outputName, policy.Data.Outputs[outputName])
	return hasChanged
}

func reportOutputHealth(ctx context.Context, bulker bulk.Bulk, zlog zerolog.Logger) {
	//pinging logic
	bulkerMap := bulker.GetBulkerMap()
	for outputName, outputBulker := range bulkerMap {
		if isOutputCfgOutdated(ctx, bulker, zlog, outputName) {
			continue
		}
		doc := model.OutputHealth{
			Output:  outputName,
			State:   client.UnitStateHealthy.String(),
			Message: "",
		}
		res, err := outputBulker.Client().Ping(outputBulker.Client().Ping.WithContext(ctx))
		if err != nil {
			doc.State = client.UnitStateDegraded.String()
			doc.Message = fmt.Sprintf("remote ES is not reachable due to error: %s", err.Error())
			zlog.Error().Err(err).Str(logger.PolicyOutputName, outputName).Msg(doc.Message)

		} else if res.StatusCode != 200 {
			doc.State = client.UnitStateDegraded.String()
			doc.Message = fmt.Sprintf("remote ES is not reachable due to unexpected status code %d", res.StatusCode)
			zlog.Error().Err(err).Str(logger.PolicyOutputName, outputName).Msg(doc.Message)
		}
		if err := dl.CreateOutputHealth(ctx, bulker, doc); err != nil {
			zlog.Error().Err(err).Str(logger.PolicyOutputName, outputName).Msg("error writing output health")
		}
	}
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
