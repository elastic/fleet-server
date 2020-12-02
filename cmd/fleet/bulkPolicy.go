// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/saved"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

const (
	kTmplPolicyId  = "policyId"
	kTmplPolicyRev = "policyRev"
)

type PolicySub struct {
	id  string
	idx uint64
	rev uint64
	C   chan Action
}

type policyT struct {
	action Action

	subs map[uint64]PolicySub // map sub counter to channel
}

type PolicyMon struct {
	mut       sync.Mutex
	kickCh    chan struct{}
	policies  map[string]policyT
	queryTmpl *dsl.Tmpl
	throttle  time.Duration
}

var gCounter uint64

func NewPolicyMon(throttle time.Duration) (*PolicyMon, error) {

	tmpl, err := makeQueryTmpl()
	if err != nil {
		return nil, err
	}

	pm := &PolicyMon{
		kickCh:    make(chan struct{}),
		policies:  make(map[string]policyT),
		queryTmpl: tmpl,
		throttle:  throttle,
	}

	return pm, nil
}

func (pm *PolicyMon) Monitor(ctx context.Context, sv saved.CRUD) error {
	var err error

	freq := time.Second * 5 // TODO: option
	tick := time.NewTicker(freq)
	defer tick.Stop()

LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case <-pm.kickCh:
			if e := pm.Process(ctx, sv); e != nil {
				log.Error().Err(e).Msg("Fail policy process due to kick")
			}
		case <-tick.C:
			if e := pm.Process(ctx, sv); e != nil {
				log.Error().Err(e).Msg("Fail policy process due")
			}
		}
	}

	// TODO: GC unused policies

	return err
}

func (pm *PolicyMon) getLatestAction(ctx context.Context, sv saved.CRUD, id string, rev uint64) (*Action, error) {

	m := map[string]interface{}{
		kTmplPolicyId:  id,
		kTmplPolicyRev: rev,
	}

	d, err := pm.queryTmpl.Render(m)

	if err != nil {
		return nil, err
	}

	hits, err := sv.FindRaw(ctx, d)
	if err != nil {
		return nil, err
	}

	// Interpret the hits
	if len(hits) == 0 {
		return nil, nil
	}

	var action Action
	if err = sv.Decode(hits[0], &action); err != nil {
		return nil, err
	}

	action.Id = hits[0].Id

	gCache.SetAction(action.Id, action, int64(len(hits[0].Data)))

	return &action, err
}

func (pm *PolicyMon) Process(ctx context.Context, sv saved.CRUD) error {
	var err error

	type respT struct {
		err      error
		action   *Action
		policyId string
	}
	ch := make(chan respT)

	var numPolicies = 0

	// Gather the set of policy_id's and revisions to query on
	pm.mut.Lock()
	for policyId, p := range pm.policies {
		numPolicies += 1

		go func(id string, rev uint64) {
			action, err := pm.getLatestAction(ctx, sv, id, rev)
			select {
			case ch <- respT{err, action, id}:
			case <-ctx.Done():
			}

		}(policyId, p.action.PolicyRev)
	}
	pm.mut.Unlock()

	if numPolicies == 0 {
		log.Trace().Msg("No policy to monitor")
		return nil
	}

	var nResp int

LOOP:
	for nResp < numPolicies {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			break LOOP
		case r := <-ch:
			nResp += 1
			if r.err != nil {
				log.Error().
					Err(r.err).
					Str("policyId", r.policyId).
					Msg("Fail retrieve latest action")
			} else if perr := pm.rollout(ctx, r.policyId, r.action); perr != nil {
				log.Error().
					Err(perr).
					Str("policyId", r.policyId).
					Msg("Fail action rollout")
			}
		}
	}

	return err
}

func (pm *PolicyMon) rollout(ctx context.Context, policyId string, action *Action) error {

	zlog := log.With().Str("policyId", policyId).Logger()

	if action == nil {
		zlog.Trace().Msg("No new action on policy")
		return nil
	}

	if action.PolicyId != policyId {
		return errors.New("policy id mismatch response")
	}

	subs, err := pm.updatePolicy(policyId, action)

	if err != nil {
		return err
	}

	if len(subs) == 0 {
		zlog.Info().Msg("No pending subscriptions to revised policy")
		return nil
	}

	// Not holding the mutex, however, we are blocking the main processing loop.
	// No more lookups will occur will this is rolling out.
	// This is by design; there is an optional throttle here.  The queue will roll
	// out before any new revisions are detected and will slow based on throttle.
	// Note: We may want a more sophisticated system that detects new revisions during
	// a throttled rollout; but that is TBD.

	var throttle *time.Ticker
	if pm.throttle != time.Duration(0) {
		throttle = time.NewTicker(pm.throttle)
		defer throttle.Stop()
	}

	start := time.Now()

	zlog.Info().
		Int("nSubs", len(subs)).
		Dur("throttle", pm.throttle).
		Msg("Policy rollout begin")

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
		case s.C <- *action:
		default:
			// Should never block on a channel; we created a channel of size one.
			// A block here indicates a logic error somewheres.
			log.Error().
				Str("policyId", policyId).
				Msg("Should never block on policy channel")
		}

	}

	zlog.Info().
		Err(err).
		Dur("tdiff", time.Since(start)).
		Msg("Policy rollout end")

	return err
}

// Update date structures, this holds the lock;
// Return queue of pending channels.
func (pm *PolicyMon) updatePolicy(policyId string, action *Action) ([]PolicySub, error) {

	pm.mut.Lock()
	defer pm.mut.Unlock()

	// Grab the policyT by policyId
	p, ok := pm.policies[policyId]
	if !ok {
		log.Error().Str("policyId", policyId).Msg("Policy no longer exists")
		return nil, nil
	}

	log.Info().
		Str("policyId", policyId).
		Uint64("orev", p.action.PolicyRev).
		Uint64("nrev", action.PolicyRev).
		RawJSON("data", []byte(action.Data)).
		Msg("New policy")

	p.action = *action

	pm.policies[policyId] = p

	subs := make([]PolicySub, 0, len(p.subs))
	for idx, sub := range p.subs {
		if sub.rev < p.action.PolicyRev {
			// These subscriptions are one shot; delete from map.
			delete(p.subs, idx)
			subs = append(subs, sub)
		}
	}

	return subs, nil
}

func (pm *PolicyMon) Subscribe(id string, rev uint64) (*PolicySub, error) {
	if _, err := uuid.FromString(id); err != nil {
		return nil, err
	}

	idx := atomic.AddUint64(&gCounter, 1)

	s := PolicySub{
		id:  id,
		idx: idx,
		rev: rev,
		C:   make(chan Action, 1),
	}

	pm.mut.Lock()
	policy, ok := pm.policies[id]
	if policy.action.PolicyRev > rev {
		// fill the channel, clear out id; no point putting it in map as it is already fired
		s.idx = 0
		s.C <- policy.action
	} else {
		if !ok {
			policy = policyT{subs: make(map[uint64]PolicySub)}
			pm.policies[id] = policy

			select {
			case pm.kickCh <- struct{}{}:
			default:
				log.Info().Msg("Kick channel full")
			}
		}
		policy.subs[idx] = s
	}
	pm.mut.Unlock()

	return &s, nil
}

func (pm *PolicyMon) Unsubscribe(sub PolicySub) error {
	if sub.idx == 0 {
		return nil
	}

	pm.mut.Lock()
	if policy, ok := pm.policies[sub.id]; ok {
		delete(policy.subs, sub.idx)
	}
	pm.mut.Unlock()

	return nil
}

func makeQueryTmpl() (*dsl.Tmpl, error) {
	sfunc := saved.ScopeFunc(AGENT_ACTION_SAVED_OBJECT_TYPE)

	tmpl := dsl.NewTmpl()
	tokenPolicyId := tmpl.Bind(kTmplPolicyId)
	tokenPolicyRev := tmpl.Bind(kTmplPolicyRev)

	root := saved.NewQuery(AGENT_ACTION_SAVED_OBJECT_TYPE)
	root.Size(1)
	root.Sort().SortOrder(sfunc("created_at"), dsl.SortDescend)

	mustNode := root.Query().Bool().Must()
	mustNode.Term(sfunc("policy_id"), tokenPolicyId, nil)
	mustNode.Range(sfunc("policy_revision"), dsl.WithRangeGT(tokenPolicyRev))

	err := tmpl.Resolve(root)
	return tmpl, err
}
