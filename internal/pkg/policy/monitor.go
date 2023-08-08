// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
)

const cloudPolicyID = "policy-elastic-agent-on-cloud"

/*
Design should have the following properties

Policy rollout scheduling should...
1) be fair; delivered in first come first server order.
2) be throttled to avoid uncontrolled impact on resources, particularly CPU.
3) adapt to subscribers that drop offline.
4) attempt to deliver the latest policy to each subscriber at the time of delivery.
5) prioritize delivery to agents that supervise fleet-servers.

This implementation addresses the above issues by queuing subscription requests per
policy, and moving requests to the pending queue when the requirement is met; ie.
the policy is updateable.

If the subscription is unsubscribed (ie. the agent drops offline), this implementation
will remove the subscription request from its current location in either the waiting
queue on the policy or the pending queue.

Ordering is achieved with a simple double linked list implementation that allows object
migration across queues, and O(1) unlink without knowledge about which queue the subscription
is in.
*/

type Subscription interface {
	// Output returns a new policy that needs to be sent based on the current subscription.
	Output() <-chan *ParsedPolicy
}

type Monitor interface {
	// Run runs the monitor.
	Run(ctx context.Context) error

	// Subscribe creates a new subscription for a policy update.
	Subscribe(agentID string, policyID string, revisionIdx int64, coordinatorIdx int64) (Subscription, error)

	// Unsubscribe removes the current subscription.
	Unsubscribe(sub Subscription) error
}

type policyFetcher func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error)

type policyT struct {
	pp   ParsedPolicy
	head *subT
}

type monitorT struct {
	log zerolog.Logger

	mut     sync.Mutex
	bulker  bulk.Bulk
	monitor monitor.Monitor

	kickCh   chan struct{}
	deployCh chan struct{}

	policies map[string]policyT
	pendingQ *subT

	policyF       policyFetcher
	policiesIndex string
	throttle      time.Duration

	startCh chan struct{}
}

// NewMonitor creates the policy monitor for subscribing agents.
func NewMonitor(bulker bulk.Bulk, monitor monitor.Monitor, throttle time.Duration) Monitor {
	return &monitorT{
		log:           log.With().Str("ctx", "policy agent monitor").Logger(),
		bulker:        bulker,
		monitor:       monitor,
		kickCh:        make(chan struct{}, 1),
		deployCh:      make(chan struct{}, 1),
		policies:      make(map[string]policyT),
		pendingQ:      makeHead(),
		throttle:      throttle,
		policyF:       dl.QueryLatestPolicies,
		policiesIndex: dl.FleetPolicies,
		startCh:       make(chan struct{}),
	}
}

// Run runs the monitor.
func (m *monitorT) Run(ctx context.Context) error {
	m.log.Info().
		Dur("throttle", m.throttle).
		Msg("run policy monitor")

	s := m.monitor.Subscribe()
	defer m.monitor.Unsubscribe(s)

	// If no throttle set, setup a minimal spin rate.
	dur := m.throttle
	if dur == 0 {
		dur = time.Nanosecond
	}

	isDeploying := true
	ticker := time.NewTicker(dur)

	startDeploy := func() {
		if !isDeploying {
			isDeploying = true
			ticker = time.NewTicker(dur)
		}
	}

	stopDeploy := func() {
		ticker.Stop()
		isDeploying = false
	}

	// begin in stopped state
	stopDeploy()

	// stop timer on exit
	defer stopDeploy()

	close(m.startCh)

LOOP:
	for {
		select {
		case <-m.kickCh:
			if err := m.loadPolicies(ctx); err != nil {
				return err
			}
			startDeploy()
		case <-m.deployCh:
			startDeploy()
		case hits := <-s.Output():
			if err := m.processHits(ctx, hits); err != nil {
				return err
			}
			startDeploy()
		case <-ticker.C:
			if done := m.dispatchPending(); done {
				stopDeploy()
			}
		case <-ctx.Done():
			break LOOP
		}
	}

	return nil
}

func unmarshalHits(hits []es.HitT) ([]model.Policy, error) {

	policies := make([]model.Policy, len(hits))
	for i, hit := range hits {
		err := hit.Unmarshal(&policies[i])
		if err != nil {
			return nil, err
		}
	}

	return policies, nil
}

func (m *monitorT) processHits(ctx context.Context, hits []es.HitT) error {
	policies, err := unmarshalHits(hits)
	if err != nil {
		m.log.Error().Err(err).Msg("fail unmarshal hits")
		return err
	}

	return m.processPolicies(ctx, policies)
}

func (m *monitorT) waitStart(ctx context.Context) error { //nolint:unused // not sure if this is used in tests
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.startCh:
	}
	return nil
}

func (m *monitorT) dispatchPending() bool {
	m.mut.Lock()
	defer m.mut.Unlock()

	s := m.pendingQ.popFront()
	if s == nil {
		return true
	}

	done := m.pendingQ.isEmpty()

	// Lookup the latest policy for this subscription
	policy, ok := m.policies[s.policyID]
	if !ok {
		m.log.Warn().
			Str(logger.PolicyID, s.policyID).
			Msg("logic error: policy missing on dispatch")
		return done
	}

	select {
	case s.ch <- &policy.pp:
		m.log.Debug().
			Str(logger.AgentID, s.agentID).
			Str(logger.PolicyID, s.policyID).
			Int64("rev", s.revIdx).
			Int64("coord", s.coordIdx).
			Msg("dispatch")
	default:
		// Should never block on a channel; we created a channel of size one.
		// A block here indicates a logic error somewheres.
		m.log.Error().
			Str(logger.PolicyID, s.policyID).
			Str(logger.AgentID, s.agentID).
			Msg("logic error: should never block on policy channel")
	}

	return done
}

func (m *monitorT) loadPolicies(ctx context.Context) error {
	policies, err := m.policyF(ctx, m.bulker, dl.WithIndexName(m.policiesIndex))
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			m.log.Debug().
				Str("index", m.policiesIndex).
				Msg(es.ErrIndexNotFound.Error())
			return nil
		}
		return err
	}
	if len(policies) == 0 {
		m.log.Debug().Msg("no policy to monitor")
		return nil
	}
	return m.processPolicies(ctx, policies)
}

func (m *monitorT) processPolicies(ctx context.Context, policies []model.Policy) error {
	if len(policies) == 0 {
		return nil
	}

	latest := m.groupByLatest(policies)
	for _, policy := range latest {
		pp, err := NewParsedPolicy(ctx, policy, m.bulker)
		if err != nil {
			return err
		}

		m.updatePolicy(pp)
	}
	return nil
}

func groupByLatest(policies []model.Policy) map[string]model.Policy {
	latest := make(map[string]model.Policy)
	for _, policy := range policies {
		curr, ok := latest[policy.PolicyID]
		if !ok {
			latest[policy.PolicyID] = policy
			continue
		}
		if policy.RevisionIdx > curr.RevisionIdx {
			latest[policy.PolicyID] = policy
			continue
		} else if policy.RevisionIdx == curr.RevisionIdx && policy.CoordinatorIdx > curr.CoordinatorIdx {
			latest[policy.PolicyID] = policy
		}
	}
	return latest
}

func (m *monitorT) groupByLatest(policies []model.Policy) map[string]model.Policy {
	return groupByLatest(policies)
}

func (m *monitorT) updatePolicy(pp *ParsedPolicy) bool {
	newPolicy := pp.Policy

	zlog := m.log.With().
		Str(logger.PolicyID, newPolicy.PolicyID).
		Int64("rev", newPolicy.RevisionIdx).
		Int64("coord", newPolicy.CoordinatorIdx).
		Logger()

	if newPolicy.CoordinatorIdx <= 0 {
		zlog.Info().Str(logger.PolicyID, newPolicy.PolicyID).Msg("Ignore policy that has not passed through coordinator")
		return false
	}

	m.mut.Lock()
	defer m.mut.Unlock()

	p, ok := m.policies[newPolicy.PolicyID]
	if !ok {
		p = policyT{
			pp:   *pp,
			head: makeHead(),
		}
		m.policies[newPolicy.PolicyID] = p
		zlog.Info().Str(logger.PolicyID, newPolicy.PolicyID).Msg("New policy found on update and added")
		return false
	}

	// Cache the old stored policy for logging
	oldPolicy := p.pp.Policy

	// Update the policy in our data structure
	p.pp = *pp
	m.policies[newPolicy.PolicyID] = p

	// Iterate through the subscriptions on this policy;
	// schedule any subscription for delivery that requires an update.
	nQueued := 0

	iter := NewIterator(p.head)
	for sub := iter.Next(); sub != nil; sub = iter.Next() {
		if sub.isUpdate(&newPolicy) {

			// Unlink the target node from the list
			iter.Unlink()

			// Push the node onto the pendingQ
			// HACK: if update is for cloud agent, put on front of queue
			// not at the end for immediate delivery.
			if newPolicy.PolicyID == cloudPolicyID {
				m.pendingQ.pushFront(sub)
			} else {
				m.pendingQ.pushBack(sub)
			}

			zlog.Debug().
				Str(logger.AgentID, sub.agentID).
				Msg("scheduled pendingQ on policy revision")

			nQueued += 1
		}
	}

	zlog.Info().
		Int64("oldRev", oldPolicy.RevisionIdx).
		Int64("oldCoord", oldPolicy.CoordinatorIdx).
		Int("nQueued", nQueued).
		Str(logger.PolicyID, newPolicy.PolicyID).
		Msg("New revision of policy received and added to the queue")

	return true
}

func (m *monitorT) kickLoad() {

	select {
	case m.kickCh <- struct{}{}:
	default:
		m.log.Debug().Msg("kick channel full")
	}
}

func (m *monitorT) kickDeploy() {

	select {
	case m.deployCh <- struct{}{}:
	default:
	}
}

// Subscribe creates a new subscription for a policy update.
func (m *monitorT) Subscribe(agentID string, policyID string, revisionIdx int64, coordinatorIdx int64) (Subscription, error) {
	if revisionIdx < 0 {
		return nil, errors.New("revisionIdx must be greater than or equal to 0")
	}
	if coordinatorIdx < 0 {
		return nil, errors.New("coordinatorIdx must be greater than or equal to 0")
	}

	m.log.Debug().
		Str(logger.AgentID, agentID).
		Str(logger.PolicyID, policyID).
		Int64("rev", revisionIdx).
		Int64("coord", coordinatorIdx).
		Msg("subscribed to policy monitor")

	s := NewSub(
		policyID,
		agentID,
		revisionIdx,
		coordinatorIdx,
	)

	m.mut.Lock()
	defer m.mut.Unlock()
	p, ok := m.policies[policyID]

	switch {
	case !ok:
		// We've not seen this policy before, force load.
		m.log.Info().
			Str(logger.PolicyID, policyID).
			Msg("force load on unknown policyId")
		p = policyT{head: makeHead()}
		p.head.pushBack(s)
		m.policies[policyID] = p
		m.kickLoad()
	case s.isUpdate(&p.pp.Policy):
		empty := m.pendingQ.isEmpty()
		m.pendingQ.pushBack(s)
		m.log.Debug().
			Str(logger.AgentID, s.agentID).
			Msg("scheduled pending on subscribe")
		if empty {
			m.kickDeploy()
		}
	default:
		p.head.pushBack(s)
	}

	return s, nil
}

// Unsubscribe removes the current subscription.
func (m *monitorT) Unsubscribe(sub Subscription) error {
	s, ok := sub.(*subT)
	if !ok {
		return errors.New("not a subscription returned from this monitor")
	}

	m.mut.Lock()
	s.unlink()
	m.mut.Unlock()

	m.log.Debug().
		Str(logger.AgentID, s.agentID).
		Str(logger.PolicyID, s.policyID).
		Int64("rev", s.revIdx).
		Int64("coord", s.coordIdx).
		Msg("unsubscribe")

	return nil
}
