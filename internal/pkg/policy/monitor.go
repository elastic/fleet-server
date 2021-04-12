// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
)

var gCounter uint64

type Subscription interface {
	// Output returns a new policy that needs to be sent based on the current subscription.
	Output() <-chan *ParsedPolicy
}

type Monitor interface {
	// Run runs the monitor.
	Run(ctx context.Context) error

	// Subscribe creates a new subscription for a policy update.
	Subscribe(agentId string, policyId string, revisionIdx int64, coordinatorIdx int64) (Subscription, error)

	// Unsubscribe removes the current subscription.
	Unsubscribe(sub Subscription) error
}

type policyFetcher func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error)

type subT struct {
	idx uint64

	policyId string
	revIdx   int64
	coordIdx int64

	c chan *ParsedPolicy
}

type policyT struct {
	pp   ParsedPolicy
	subs map[uint64]subT // map sub counter to channel
}

type monitorT struct {
	log zerolog.Logger

	mut     sync.Mutex
	bulker  bulk.Bulk
	monitor monitor.Monitor

	kickCh   chan struct{}
	policies map[string]policyT

	policyF       policyFetcher
	policiesIndex string
	throttle      time.Duration
}

// Output returns a new policy that needs to be sent based on the current subscription.
func (s *subT) Output() <-chan *ParsedPolicy {
	return s.c
}

// NewMonitor creates the policy monitor for subscribing agents.
func NewMonitor(bulker bulk.Bulk, monitor monitor.Monitor, throttle time.Duration) Monitor {
	return &monitorT{
		log:           log.With().Str("ctx", "policy agent monitor").Logger(),
		bulker:        bulker,
		monitor:       monitor,
		kickCh:        make(chan struct{}, 1),
		policies:      make(map[string]policyT),
		throttle:      throttle,
		policyF:       dl.QueryLatestPolicies,
		policiesIndex: dl.FleetPolicies,
	}
}

// Run runs the monitor.
func (m *monitorT) Run(ctx context.Context) error {
	m.log.Info().Dur("throttle", m.throttle).Msg("run policy monitor")

	s := m.monitor.Subscribe()
	defer m.monitor.Unsubscribe(s)

LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case <-m.kickCh:
			if err := m.process(ctx); err != nil {
				return err
			}
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

func (m *monitorT) process(ctx context.Context) error {
	policies, err := m.policyF(ctx, m.bulker, dl.WithIndexName(m.policiesIndex))
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			m.log.Debug().Str("index", m.policiesIndex).Msg(es.ErrIndexNotFound.Error())
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
		// nothing to do
		return nil
	}
	latest := m.groupByLatest(policies)
	for _, policy := range latest {
		if err := m.rollout(ctx, policy); err != nil {
			if err == context.Canceled {
				return err
			}
			return fmt.Errorf("failed rolling out policy %s: %w", policy.PolicyId, err)
		}
	}
	return nil
}

func (m *monitorT) groupByLatest(policies []model.Policy) map[string]model.Policy {
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

func (m *monitorT) rollout(ctx context.Context, policy model.Policy) error {
	zlog := m.log.With().Str("policyId", policy.PolicyId).Logger()

	pp, err := NewParsedPolicy(policy)
	if err != nil {
		return err
	}

	subs := m.updatePolicy(pp)
	if subs == nil {
		return nil
	}
	if len(subs) == 0 {
		zlog.Info().Msg("no pending subscriptions to revised policy")
		return nil
	}

	// Not holding the mutex, however, we are blocking the main processing loop.
	// No more lookups will occur will this is rolling out.
	// This is by design; there is an optional throttle here.  The queue will roll
	// out before any new revisions are detected and will slow based on throttle.
	// Note: We may want a more sophisticated system that detects new revisions during
	// a throttled rollout; but that is TBD.

	var throttle *time.Ticker
	if m.throttle != time.Duration(0) {
		throttle = time.NewTicker(m.throttle)
		defer throttle.Stop()
	}

	start := time.Now()

	zlog.Info().
		Int("nSubs", len(subs)).
		Dur("throttle", m.throttle).
		Msg("policy rollout begin")

LOOP:
	for _, s := range subs {

		if throttle != nil {
			select {
			case <-throttle.C:
			case <-ctx.Done():
				err = ctx.Err()
				break LOOP
			}
		}

		select {
		case s.c <- pp:
		default:
			// Should never block on a channel; we created a channel of size one.
			// A block here indicates a logic error somewheres.
			zlog.Error().
				Str("policyId", policy.PolicyId).
				Msg("should never block on policy channel")
		}

	}

	zlog.Info().
		Err(err).
		Dur("tdiff", time.Since(start)).
		Msg("policy rollout end")

	return err
}

func (m *monitorT) updatePolicy(pp *ParsedPolicy) []subT {
	m.mut.Lock()
	defer m.mut.Unlock()

	newPolicy := pp.Policy

	p, ok := m.policies[newPolicy.PolicyId]
	if !ok {
		p = policyT{
			pp:   *pp,
			subs: make(map[uint64]subT),
		}
		m.policies[newPolicy.PolicyId] = p
		m.log.Info().
			Str("policyId", newPolicy.PolicyId).
			Int64("rev", newPolicy.RevisionIdx).
			Int64("coord", newPolicy.CoordinatorIdx).
			Msg("new policy")
		return nil
	}

	oldPolicy := p.pp.Policy

	p.pp = *pp
	m.policies[newPolicy.PolicyId] = p

	m.log.Info().
		Str("policyId", newPolicy.PolicyId).
		Int64("orev", oldPolicy.RevisionIdx).
		Int64("nrev", newPolicy.RevisionIdx).
		Int64("ocoord", oldPolicy.CoordinatorIdx).
		Int64("ncoord", newPolicy.CoordinatorIdx).
		Msg("policy revised")

	if newPolicy.CoordinatorIdx <= 0 {
		m.log.Info().
			Str("policyId", newPolicy.PolicyId).
			Msg("Do not roll out policy that has not pass through coordinator")
		return nil
	}

	subs := make([]subT, 0, len(p.subs))
	for idx, sub := range p.subs {
		if newPolicy.RevisionIdx > sub.revIdx ||
			(newPolicy.RevisionIdx == sub.revIdx && newPolicy.CoordinatorIdx > sub.coordIdx) {
			// These subscriptions are one shot; delete from map.
			delete(p.subs, idx)
			subs = append(subs, sub)
		}
	}

	return subs
}

// Subscribe creates a new subscription for a policy update.
func (m *monitorT) Subscribe(agentId string, policyId string, revisionIdx int64, coordinatorIdx int64) (Subscription, error) {
	if _, err := uuid.FromString(policyId); err != nil {
		return nil, errors.New("policyId must be a UUID")
	}
	if revisionIdx < 0 {
		return nil, errors.New("revisionIdx must be greater than or equal to 0")
	}
	if coordinatorIdx < 0 {
		return nil, errors.New("coordinatorIdx must be greater than or equal to 0")
	}

	m.log.Debug().
		Str("agentId", agentId).
		Str("policyId", policyId).
		Int64("revno", revisionIdx).
		Int64("coordno", coordinatorIdx).
		Msg("subscribed to policy monitor")

	idx := atomic.AddUint64(&gCounter, 1)

	s := subT{
		idx:      idx,
		policyId: policyId,
		revIdx:   revisionIdx,
		coordIdx: coordinatorIdx,
		c:        make(chan *ParsedPolicy, 1),
	}

	m.mut.Lock()
	p, ok := m.policies[policyId]

	pRevIdx := p.pp.Policy.RevisionIdx
	pCoordIdx := p.pp.Policy.CoordinatorIdx

	if (pRevIdx > revisionIdx && pCoordIdx > 0) ||
		(pRevIdx == revisionIdx && pCoordIdx > coordinatorIdx) {
		// fill the channel, clear out id; no point putting it in map as it is already fired
		s.idx = 0
		s.c <- &p.pp
	} else {
		if !ok {
			p = policyT{subs: make(map[uint64]subT)}
			m.policies[policyId] = p
			select {
			case m.kickCh <- struct{}{}:
			default:
				m.log.Debug().Msg("kick channel full")
			}
		}
		p.subs[idx] = s
	}
	m.mut.Unlock()

	return &s, nil
}

// Unsubscribe removes the current subscription.
func (m *monitorT) Unsubscribe(sub Subscription) error {
	s, ok := sub.(*subT)
	if !ok {
		return errors.New("not a subscription returned from this monitor")
	}
	if s.idx == 0 {
		return nil
	}

	m.mut.Lock()
	if policy, ok := m.policies[s.policyId]; ok {
		delete(policy.subs, s.idx)
	}
	m.mut.Unlock()

	return nil
}
