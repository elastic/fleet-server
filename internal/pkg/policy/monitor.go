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
	"go.elastic.co/apm/v2"
	"golang.org/x/time/rate"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
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
	limit         *rate.Limiter

	startCh chan struct{}
}

// NewMonitor creates the policy monitor for subscribing agents.
func NewMonitor(bulker bulk.Bulk, monitor monitor.Monitor, cfg config.ServerLimits) Monitor {
	burst := cfg.PolicyLimit.Burst
	interval := rate.Every(cfg.PolicyLimit.Interval)
	if cfg.PolicyLimit.Burst <= 0 {
		burst = 1
	}
	if cfg.PolicyLimit.Interval <= 0 {
		if cfg.PolicyThrottle > 0 { // use the old throttle if it's defined and the limit.Interval is not.
			interval = rate.Every(cfg.PolicyThrottle)
		} else {
			interval = rate.Every(time.Nanosecond) // set minimal spin rate
		}
	}
	return &monitorT{
		bulker:        bulker,
		monitor:       monitor,
		kickCh:        make(chan struct{}, 1),
		deployCh:      make(chan struct{}, 1),
		policies:      make(map[string]policyT),
		pendingQ:      makeHead(),
		limit:         rate.NewLimiter(interval, burst),
		policyF:       dl.QueryLatestPolicies,
		policiesIndex: dl.FleetPolicies,
		startCh:       make(chan struct{}),
	}
}

// endTrans is a convenience function to end the passed transaction if it's not nil
func endTrans(t *apm.Transaction) {
	if t != nil {
		t.End()
	}
}

// Run runs the monitor.
func (m *monitorT) Run(ctx context.Context) error {
	m.log = zerolog.Ctx(ctx).With().Str("ctx", "policy agent monitor").Logger()
	m.log.Info().
		Int("burst", m.limit.Burst()).
		Any("event_rate", m.limit.Limit()). // Limit() returns an alias type for float64
		Msg("run policy monitor")

	s := m.monitor.Subscribe()
	defer m.monitor.Unsubscribe(s)

	close(m.startCh)

	var iCtx context.Context
	var trans *apm.Transaction
LOOP:
	for {
		m.log.Debug().Msg("policy monitor loop start")
		iCtx = ctx
		select {
		case <-m.kickCh:
			m.log.Debug().Msg("policy monitor kicked")
			if m.bulker.HasTracer() {
				trans = m.bulker.StartTransaction("initial policies", "policy_monitor")
				iCtx = apm.ContextWithTransaction(ctx, trans)
			}

			if err := m.loadPolicies(iCtx); err != nil {
				endTrans(trans)
				return err
			}
			m.dispatchPending(iCtx)
			endTrans(trans)
		case <-m.deployCh:
			m.log.Debug().Msg("policy monitor deploy ch")
			if m.bulker.HasTracer() {
				trans = m.bulker.StartTransaction("forced policies", "policy_monitor")
				iCtx = apm.ContextWithTransaction(ctx, trans)
			}

			m.dispatchPending(iCtx)
			endTrans(trans)
		case hits := <-s.Output(): // TODO would be nice to attach transaction IDs to hits, but would likely need a bigger refactor.
			m.log.Debug().Int("hits", len(hits)).Msg("policy monitor hits from sub")
			if m.bulker.HasTracer() {
				trans = m.bulker.StartTransaction("output policies", "policy_monitor")
				iCtx = apm.ContextWithTransaction(ctx, trans)
			}

			if err := m.processHits(iCtx, hits); err != nil {
				endTrans(trans)
				return err
			}
			m.dispatchPending(iCtx)
			endTrans(trans)
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
	span, ctx := apm.StartSpan(ctx, "process hits", "process")
	defer span.End()

	policies, err := unmarshalHits(hits)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Msg("fail unmarshal hits")
		return err
	}

	return m.processPolicies(ctx, policies)
}

// waitStart returns once Run has started
// It's used in tests.
func (m *monitorT) waitStart(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.startCh:
	}
	return nil
}

// dispatchPending will dispatch all pending policy changes to the subscriptions in the queue.
// dispatches are rate limited by the monitor's limiter.
func (m *monitorT) dispatchPending(ctx context.Context) {
	span, ctx := apm.StartSpan(ctx, "dispatch pending", "dispatch")
	defer span.End()
	m.mut.Lock()
	defer m.mut.Unlock()

	ts := time.Now()
	defer func(ts time.Time) {
		m.log.Debug().Dur("duration", time.Since(ts)).Msg("policy monitor dispatch complete")
	}(ts)

	s := m.pendingQ.popFront()
	if s == nil {
		return
	}

	for s != nil {
		// Use a rate.Limiter to control how fast policies are passed to the checkin handler.
		// This is done to avoid all responses to agents on the same policy from being written at once.
		// If too many (checkin) responses are written concurrently memory usage may explode due to allocating gzip writers.
		err := m.limit.Wait(ctx)
		if err != nil {
			m.log.Error().Err(err).Msg("Policy limit error")
			return
		}
		// Lookup the latest policy for this subscription
		policy, ok := m.policies[s.policyID]
		if !ok {
			m.log.Warn().
				Str(logger.PolicyID, s.policyID).
				Msg("logic error: policy missing on dispatch")
			return
		}

		select {
		case <-ctx.Done():
			m.log.Debug().Err(ctx.Err()).Msg("context termination detected in policy dispatch")
			return
		case s.ch <- &policy.pp:
			m.log.Debug().
				Str(logger.AgentID, s.agentID).
				Str(logger.PolicyID, s.policyID).
				Int64("subscription_revision_idx", s.revIdx).
				Int64("subscription_coordinator_idx", s.coordIdx).
				Int64("revision_idx", policy.pp.Policy.RevisionIdx).
				Int64("coordinator_idx", policy.pp.Policy.CoordinatorIdx).
				Msg("dispatch")
		default:
			// Should never block on a channel; we created a channel of size one.
			// A block here indicates a logic error somewheres.
			m.log.Error().
				Str(logger.PolicyID, s.policyID).
				Str(logger.AgentID, s.agentID).
				Msg("logic error: should never block on policy channel")
			return
		}
		s = m.pendingQ.popFront()
	}
}

func (m *monitorT) loadPolicies(ctx context.Context) error {
	span, ctx := apm.StartSpan(ctx, "Load policies", "load")
	defer span.End()

	if m.bulker.HasTracer() {
		tctx := span.TraceContext()
		trans := m.bulker.StartTransactionOptions("Load policies", "bulker", apm.TransactionOptions{Links: []apm.SpanLink{{
			Trace: tctx.Trace,
			Span:  tctx.Span,
		}}})
		ctx = apm.ContextWithTransaction(ctx, trans)
		defer trans.End()
	}
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
	span, ctx := apm.StartSpan(ctx, "process policies", "process")
	defer span.End()

	if len(policies) == 0 {
		return nil
	}

	m.log.Debug().Int64(dl.FieldRevisionIdx, policies[0].RevisionIdx).
		Int64(dl.FieldCoordinatorIdx, policies[0].CoordinatorIdx).
		Str(logger.PolicyID, policies[0].PolicyID).Msg("process policies")

	latest := m.groupByLatest(policies)
	for _, policy := range latest {
		pp, err := NewParsedPolicy(ctx, m.bulker, policy)
		if err != nil {
			return err
		}

		m.updatePolicy(ctx, pp)
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

func (m *monitorT) updatePolicy(ctx context.Context, pp *ParsedPolicy) bool {
	newPolicy := pp.Policy

	span, _ := apm.StartSpan(ctx, "update policy", "process")
	span.Context.SetLabel(logger.PolicyID, newPolicy.PolicyID)
	span.Context.SetLabel("revision_idx", newPolicy.RevisionIdx)
	span.Context.SetLabel("coordinator_idx", newPolicy.CoordinatorIdx)
	defer span.End()

	zlog := m.log.With().
		Str(logger.PolicyID, newPolicy.PolicyID).
		Int64("revision_idx", newPolicy.RevisionIdx).
		Int64("coordinator_idx", newPolicy.CoordinatorIdx).
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
	zlog.Debug().Str(logger.PolicyID, newPolicy.PolicyID).Msg("Update policy revision")

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
		Int64("old_revision_idx", oldPolicy.RevisionIdx).
		Int64("old_coordinator_idx", oldPolicy.CoordinatorIdx).
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
		Int64("revision_idx", revisionIdx).
		Int64("coordinator_idx", coordinatorIdx).
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
			Str(logger.AgentID, s.agentID).
			Msg("force load on unknown policyId")
		p = policyT{head: makeHead()}
		p.head.pushBack(s)
		m.policies[policyID] = p
		m.kickLoad()
	case s.isUpdate(&p.pp.Policy):
		empty := m.pendingQ.isEmpty()
		if empty {
			m.pendingQ.pushBack(s)
			m.log.Debug().
				Str(logger.AgentID, s.agentID).
				Msg("deploy pending on subscribe, empty queue")
			m.kickDeploy()
		} else {
			m.log.Debug().
				Str(logger.PolicyID, policyID).
				Str(logger.AgentID, s.agentID).
				Int64("revision_idx", (&p.pp.Policy).RevisionIdx).
				Msg("policy subscription added, queue not empty")
			p.head.pushBack(s)
		}
	default:
		m.log.Debug().
			Str(logger.PolicyID, policyID).
			Str(logger.AgentID, s.agentID).
			Int64("revision_idx", (&p.pp.Policy).RevisionIdx).
			Msg("subscription added without new revision")
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
		Int64("revision_idx", s.revIdx).
		Int64("coordinator_idx", s.coordIdx).
		Msg("unsubscribe")

	return nil
}
