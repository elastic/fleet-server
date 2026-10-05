// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	mmock "github.com/elastic/fleet-server/v7/internal/pkg/monitor/mock"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

var policyDataDefault = &model.PolicyData{
	Outputs: map[string]map[string]any{
		"default": map[string]any{
			"type": "elasticsearch",
		},
	},
}

func TestNewMonitor(t *testing.T) {
	tests := []struct {
		name  string
		cfg   config.ServerLimits
		burst int
		rate  float64
	}{{
		name:  "no settings",
		cfg:   config.ServerLimits{},
		burst: 1,
		rate:  float64(rate.Every(time.Nanosecond)),
	}, {
		name:  "limit specified",
		cfg:   config.ServerLimits{PolicyLimit: config.Limit{Burst: 2, Interval: time.Second}},
		burst: 2,
		rate:  1,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			M := NewMonitor(nil, nil, tc.cfg)
			m, ok := M.(*monitorT)
			require.True(t, ok, "Expected to be able to cast Monitor as monitorT")
			assert.Equal(t, tc.burst, m.limit.Burst())
			assert.Equal(t, tc.rate, float64(m.limit.Limit()))

		})
	}
}

func TestMonitor_NewPolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()

	monitor := NewMonitor(bulker, mm, config.ServerLimits{})
	pm := monitor.(*monitorT)
	pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Go(func() {
		merr = monitor.Run(ctx)
	})

	err := monitor.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentId := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyID, 0)
	defer monitor.Unsubscribe(s)
	require.NoError(t, err)

	rId := xid.New().String()
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:    policyID,
		Data:        policyDataDefault,
		RevisionIdx: 1,
	}
	policyData, err := json.Marshal(&policy)
	require.NoError(t, err)

	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   1,
		Version: 1,
		Source:  policyData,
	}}

	timedout := false
	tm := time.NewTimer(2 * time.Second)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		diff := cmp.Diff(policy, subPolicy.Policy)
		require.Empty(t, diff)
	case <-tm.C:
		timedout = true
	}

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
	require.False(t, timedout, "never got policy update; timed out after 2s")
	ms.AssertExpectations(t)
	mm.AssertExpectations(t)
}

func TestMonitor_SamePolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()

	monitor := NewMonitor(bulker, mm, config.ServerLimits{})
	pm := monitor.(*monitorT)
	pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Go(func() {
		merr = monitor.Run(ctx)
	})

	err := monitor.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyId, 1)
	defer monitor.Unsubscribe(s)
	require.NoError(t, err)

	rId := xid.New().String()
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:    policyId,
		Data:        policyDataDefault,
		RevisionIdx: 1,
	}
	policyData, err := json.Marshal(&policy)
	require.NoError(t, err)

	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   1,
		Version: 1,
		Source:  policyData,
	}}

	gotPolicy := false
	tm := time.NewTimer(1 * time.Second)
	defer tm.Stop()
	select {
	case <-s.Output():
		gotPolicy = true
	case <-tm.C:
	}

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
	require.False(t, gotPolicy, "got policy update when it was the same rev idx")
	ms.AssertExpectations(t)
	mm.AssertExpectations(t)
}

func TestMonitor_NewPolicyExists(t *testing.T) {
	tests := []struct {
		name  string
		delay time.Duration
	}{
		{"monitor no delay", 0},

		// Tests the defect where the delay running the monitor was causing race
		// https://github.com/elastic/fleet-server/issues/48
		{"monitor with delay", 100 * time.Millisecond},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runTestMonitor_NewPolicyExists(t, tc.delay)
		})
	}
}

func runTestMonitor_NewPolicyExists(t *testing.T, delay time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()

	monitor := NewMonitor(bulker, mm, config.ServerLimits{})
	pm := monitor.(*monitorT)

	agentId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	rId := xid.New().String()
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:    policyId,
		Data:        policyDataDefault,
		RevisionIdx: 2,
	}

	pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{policy}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		time.Sleep(delay)
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	err := monitor.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	s, err := monitor.Subscribe(agentId, policyId, 1)
	defer monitor.Unsubscribe(s)
	require.NoError(t, err)

	timedout := false
	tm := time.NewTimer(2 * time.Second)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		diff := cmp.Diff(policy, subPolicy.Policy)
		require.Empty(t, diff)
	case <-tm.C:
		timedout = true
	}

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
	require.False(t, timedout, "never got policy update; timed out after 500ms")
}

// Test_Monitor_Limit_Delay ensures that the policy monitor spaces the
// dispatches of one policy revision out according to the configured policy
// limit, so that responses to agents on the same policy are not all written at
// once.
//
// The test runs inside a synctest bubble: the rate limiter's timers and
// time.Now() then run on the bubble's synthetic clock, which only advances
// once every goroutine is blocked. The dispatch delays are therefore exact.
func Test_Monitor_Limit_Delay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = 50 * time.Millisecond

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = testlog.SetLogger(t).WithContext(ctx)

		chHitT := make(chan []es.HitT, 1)
		defer close(chHitT)
		ms := mmock.NewMockSubscription()
		ms.On("Output").Return((<-chan []es.HitT)(chHitT))
		mm := mmock.NewMockMonitor()
		mm.On("Subscribe").Return(ms).Once()
		mm.On("Unsubscribe", mock.Anything).Return().Once()
		bulker := ftesting.NewMockBulk()

		monitor := NewMonitor(bulker, mm, config.ServerLimits{PolicyLimit: config.Limit{Burst: 1, Interval: interval}})
		pm := monitor.(*monitorT)
		pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
			return []model.Policy{}, nil
		}

		var merr error
		var mwg sync.WaitGroup
		mwg.Go(func() {
			merr = monitor.Run(ctx)
		})

		err := pm.waitStart(ctx)
		require.NoError(t, err)

		// Seed the policy so that subscribing does not force a policy load.
		// Handling any run loop event cancels the context of the dispatch that
		// is in flight, so keeping the hit published below as the only event
		// the run loop sees means exactly one dispatch runs, uninterrupted.
		policyID := uuid.Must(uuid.NewV4()).String()
		pm.mut.Lock()
		pm.policies[policyID] = policyT{head: makeHead()}
		pm.mut.Unlock()

		subs := make([]Subscription, 0, 3)
		for range cap(subs) {
			sub, err := monitor.Subscribe(uuid.Must(uuid.NewV4()).String(), policyID, 0)
			require.NoError(t, err)
			defer monitor.Unsubscribe(sub)
			subs = append(subs, sub)
		}

		rId := xid.New().String()
		policy := model.Policy{
			ESDocument: model.ESDocument{
				Id:      rId,
				Version: 1,
				SeqNo:   1,
			},
			PolicyID:       policyID,
			CoordinatorIdx: 1,
			Data:           policyDataDefault,
			RevisionIdx:    1,
		}
		policyData, err := json.Marshal(&policy)
		require.NoError(t, err)

		start := time.Now()
		chHitT <- []es.HitT{{
			ID:      rId,
			SeqNo:   1,
			Version: 1,
			Source:  policyData,
		}}

		// The subscriptions are dispatched in subscription order: the first one
		// consumes the limiter's initial burst and the rest are spaced out by
		// the configured interval.
		for i, sub := range subs {
			select {
			case subPolicy := <-sub.Output():
				diff := cmp.Diff(policy, subPolicy.Policy)
				require.Empty(t, diff)
				assert.Equal(t, time.Duration(i)*interval, time.Since(start), "unexpected dispatch delay for subscription %d", i)
			case <-time.After(time.Minute):
				require.FailNowf(t, "policy was not dispatched", "subscription %d never received the policy", i)
			}
		}

		cancel()
		mwg.Wait()
		if merr != nil {
			require.ErrorIs(t, merr, context.Canceled)
		}
		ms.AssertExpectations(t)
		mm.AssertExpectations(t)
	})
}

// Test_Monitor_pending_sub_gets_latest_revision ensures that a subscriber waiting in the rate
// limiter when a new revision arrives receives the new revision, not the one that was current
// when it was popped from the pending queue.
func Test_Monitor_pending_sub_gets_latest_revision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = testlog.SetLogger(t).WithContext(ctx)

		chHitT := make(chan []es.HitT, 2)
		defer close(chHitT)
		ms := mmock.NewMockSubscription()
		ms.On("Output").Return((<-chan []es.HitT)(chHitT))
		mm := mmock.NewMockMonitor()
		mm.On("Subscribe").Return(ms).Once()
		mm.On("Unsubscribe", mock.Anything).Return().Once()

		// Burst of 1 and a long interval: the first subscriber is dispatched immediately,
		// the second waits in the rate limiter.
		monitor := NewMonitor(ftesting.NewMockBulk(), mm, config.ServerLimits{PolicyLimit: config.Limit{Burst: 1, Interval: time.Hour}})
		pm := monitor.(*monitorT)
		pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
			return []model.Policy{}, nil
		}

		var mwg sync.WaitGroup
		mwg.Go(func() { _ = monitor.Run(ctx) })
		require.NoError(t, pm.waitStart(ctx))

		policyID := uuid.Must(uuid.NewV4()).String()
		pm.mut.Lock()
		pm.policies[policyID] = policyT{head: makeHead()}
		pm.mut.Unlock()

		subs := make([]Subscription, 2)
		for i := range subs {
			sub, err := monitor.Subscribe(uuid.Must(uuid.NewV4()).String(), policyID, 0)
			require.NoError(t, err)
			defer monitor.Unsubscribe(sub)
			subs[i] = sub
		}

		rId := xid.New().String()
		hit := func(seqNo, revisionIdx int64) []es.HitT {
			policyData, err := json.Marshal(&model.Policy{
				ESDocument:     model.ESDocument{Id: rId, Version: 1, SeqNo: seqNo},
				PolicyID:       policyID,
				CoordinatorIdx: 1,
				Data:           policyDataDefault,
				RevisionIdx:    revisionIdx,
			})
			require.NoError(t, err)
			return []es.HitT{{ID: rId, SeqNo: seqNo, Version: 1, Source: policyData}}
		}

		// Revision 1 reaches the first subscriber; the second waits in the limiter.
		chHitT <- hit(1, 1)
		select {
		case p := <-subs[0].Output():
			require.Equal(t, int64(1), p.Policy.RevisionIdx)
		case <-time.After(time.Minute):
			require.Fail(t, "first subscriber was not dispatched")
		}
		synctest.Wait()

		// Revision 2 arrives while the second subscriber is waiting for the limiter.
		chHitT <- hit(2, 2)

		select {
		case p := <-subs[1].Output():
			require.Equal(t, int64(2), p.Policy.RevisionIdx, "waiting subscriber must receive the latest revision")
		case <-time.After(2 * time.Hour):
			require.Fail(t, "second subscriber was never dispatched")
		}
		synctest.Wait()
		require.Empty(t, subs[1].Output(), "second subscriber must receive exactly one revision")

		cancel()
		mwg.Wait()
	})
}

func TestMonitor_LatestRev(t *testing.T) {
	t.Run("empty policy id", func(t *testing.T) {
		pm := &monitorT{}
		idx := pm.LatestRev(t.Context(), "")
		assert.Equal(t, int64(0), idx)
	})

	t.Run("policy load error", func(t *testing.T) {
		bulker := ftesting.NewMockBulk()
		mm := mmock.NewMockMonitor()
		monitor := NewMonitor(bulker, mm, config.ServerLimits{})
		pm := monitor.(*monitorT)
		pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
			return nil, fmt.Errorf("policy fetch error")
		}

		idx := pm.LatestRev(t.Context(), "test-id")
		assert.Equal(t, int64(0), idx)
	})

	t.Run("policy not found", func(t *testing.T) {
		bulker := ftesting.NewMockBulk()
		mm := mmock.NewMockMonitor()
		monitor := NewMonitor(bulker, mm, config.ServerLimits{})
		pm := monitor.(*monitorT)
		pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
			return []model.Policy{}, nil
		}
		idx := pm.LatestRev(t.Context(), "test-id")
		assert.Equal(t, int64(0), idx)
	})

	t.Run("policy found after load", func(t *testing.T) {
		bulker := ftesting.NewMockBulk()
		mm := mmock.NewMockMonitor()
		monitor := NewMonitor(bulker, mm, config.ServerLimits{})
		pm := monitor.(*monitorT)
		policyId := uuid.Must(uuid.NewV4()).String()
		rId := xid.New().String()
		policy := model.Policy{
			ESDocument: model.ESDocument{
				Id:      rId,
				Version: 1,
				SeqNo:   1,
			},
			PolicyID:    policyId,
			Data:        policyDataDefault,
			RevisionIdx: 2,
		}
		pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
			return []model.Policy{policy}, nil
		}
		idx := pm.LatestRev(t.Context(), policyId)
		assert.Equal(t, int64(2), idx)
	})

	t.Run("policy found", func(t *testing.T) {
		pm := &monitorT{
			policies: map[string]policyT{
				"test-id": policyT{
					pp: ParsedPolicy{
						Policy: model.Policy{
							RevisionIdx: 1,
						},
					},
				},
			},
		}
		idx := pm.LatestRev(t.Context(), "test-id")
		assert.Equal(t, int64(1), idx)
	})
}

// TestUpdatePolicy_NewerRevisionIsApplied verifies that updatePolicy stores an
// incoming document and returns true when its revision_idx is greater than the
// cached revision.
func TestUpdatePolicy_NewerRevisionIsApplied(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	policyID := uuid.Must(uuid.NewV4()).String()

	makePolicy := func(rev int64) ParsedPolicy {
		return ParsedPolicy{
			Policy: model.Policy{
				PolicyID:    policyID,
				RevisionIdx: rev,
				Data:        policyDataDefault,
			},
		}
	}

	pm := &monitorT{
		log: zerolog.Ctx(ctx).With().Logger(),
		policies: map[string]policyT{
			policyID: {
				pp:   makePolicy(8),
				head: makeHead(),
			},
		},
		pendingQ: makeHead(),
	}

	fresh := makePolicy(9)
	updated := pm.updatePolicy(ctx, &fresh)
	assert.True(t, updated, "expected updatePolicy to return true for newer revision")
	assert.Equal(t, int64(9), pm.policies[policyID].pp.Policy.RevisionIdx, "cached revision must be updated")
}

// failingSecretsBulk wraps MockBulk and makes ReadSecrets return an error,
// letting tests verify that secret resolution is never attempted for stale revisions.
type failingSecretsBulk struct {
	ftesting.MockBulk
}

func (b *failingSecretsBulk) ReadSecrets(_ context.Context, _ []string) (map[string]string, error) {
	return nil, fmt.Errorf("ReadSecrets must not be called for stale revisions")
}

// TestMonitor_StaleRevisionSkipsSecretResolution verifies that processPolicies
// skips NewParsedPolicy (and therefore secret resolution) for stale revisions.
// Without the pre-parse guard a stale doc with deleted secrets would fail during
// secret resolution and cause processPolicies to return an error.
func TestMonitor_StaleRevisionSkipsSecretResolution(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	policyID := uuid.Must(uuid.NewV4()).String()

	// A policy with a secret reference so that NewParsedPolicy calls ReadSecrets.
	policyWithSecret := model.Policy{
		PolicyID:    policyID,
		RevisionIdx: 7, // stale: cached is 8
		Data: &model.PolicyData{
			Outputs: map[string]map[string]any{
				"default": {"type": "elasticsearch"},
			},
			SecretReferences: []model.SecretReferencesItems{{ID: "some-secret-id"}},
		},
	}

	bulker := &failingSecretsBulk{}
	pm := &monitorT{
		log:    zerolog.Ctx(ctx).With().Logger(),
		bulker: bulker,
		policies: map[string]policyT{
			policyID: {
				pp: ParsedPolicy{
					Policy: model.Policy{
						PolicyID:    policyID,
						RevisionIdx: 8,
						Data:        policyDataDefault,
					},
				},
				head: makeHead(),
			},
		},
		pendingQ: makeHead(),
	}

	err := pm.processPolicies(ctx, []model.Policy{policyWithSecret})
	assert.NoError(t, err, "stale revision should be skipped without error, not trigger secret resolution")
	assert.Equal(t, int64(8), pm.policies[policyID].pp.Policy.RevisionIdx, "cached revision must not change for stale input")
}

// Test_Monitor_new_event_does_not_strand_subscriber_in_rate_limiter ensures that a subscriber
// waiting in the rate limiter when a new event arrives still gets its policy.
func Test_Monitor_new_event_does_not_strand_subscriber_in_rate_limiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = testlog.SetLogger(t).WithContext(ctx)

		chHitT := make(chan []es.HitT, 1)
		defer close(chHitT)
		ms := mmock.NewMockSubscription()
		ms.On("Output").Return((<-chan []es.HitT)(chHitT))
		mm := mmock.NewMockMonitor()
		mm.On("Subscribe").Return(ms).Once()
		mm.On("Unsubscribe", mock.Anything).Return().Once()

		// Burst of 1 and a long interval: the first subscriber is dispatched immediately,
		// the second blocks in the rate limiter holding the popped subscriber.
		monitor := NewMonitor(ftesting.NewMockBulk(), mm, config.ServerLimits{PolicyLimit: config.Limit{Burst: 1, Interval: time.Hour}})
		pm := monitor.(*monitorT)
		pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
			return []model.Policy{}, nil
		}
		var mwg sync.WaitGroup
		mwg.Go(func() { _ = monitor.Run(ctx) })
		require.NoError(t, pm.waitStart(ctx))

		policyID := uuid.Must(uuid.NewV4()).String()
		pm.mut.Lock()
		pm.policies[policyID] = policyT{head: makeHead()}
		pm.mut.Unlock()

		subs := make([]Subscription, 2)
		for i := range subs {
			sub, err := monitor.Subscribe(uuid.Must(uuid.NewV4()).String(), policyID, 0)
			require.NoError(t, err)
			defer monitor.Unsubscribe(sub)
			subs[i] = sub
		}

		rId := xid.New().String()
		policy := model.Policy{
			ESDocument:     model.ESDocument{Id: rId, Version: 1, SeqNo: 1},
			PolicyID:       policyID,
			CoordinatorIdx: 1,
			Data:           policyDataDefault,
			RevisionIdx:    1,
		}
		policyData, err := json.Marshal(&policy)
		require.NoError(t, err)
		chHitT <- []es.HitT{{ID: rId, SeqNo: 1, Version: 1, Source: policyData}}

		// First subscriber is dispatched; dispatch A is now rate-waiting with the second.
		select {
		case <-subs[0].Output():
		case <-time.After(time.Minute):
			require.Fail(t, "first subscriber was not dispatched")
		}
		synctest.Wait()

		// A new event arrives while the dispatcher holds subs[1] in the limiter.
		pm.kickLoad()

		// The limiter allows one send per hour. Within two hours of fake time,
		// the dispatcher must deliver subs[1].
		select {
		case p := <-subs[1].Output():
			require.Equal(t, int64(1), p.Policy.RevisionIdx)
		case <-time.After(2 * time.Hour):
			require.Fail(t, "second subscriber was stranded in pendingQ")
		}

		cancel()
		mwg.Wait()
	})
}

// Test_Monitor_repeated_events_run_a_single_dispatcher sends a burst of events while a
// subscriber waits in the rate limiter. Events must not start overlapping dispatchers, since
// each can miss a subscriber the other holds between popping it from pendingQ and sending to
// it, and the subscriber must still get its policy.
func Test_Monitor_repeated_events_run_a_single_dispatcher(t *testing.T) {
	for range 25 {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = testlog.SetLogger(t).WithContext(ctx)

			chHitT := make(chan []es.HitT, 1)
			defer close(chHitT)
			ms := mmock.NewMockSubscription()
			ms.On("Output").Return((<-chan []es.HitT)(chHitT))
			mm := mmock.NewMockMonitor()
			mm.On("Subscribe").Return(ms).Once()
			mm.On("Unsubscribe", mock.Anything).Return().Once()

			// Burst of 1 and a long interval: the first subscriber is dispatched immediately,
			// the second waits in the rate limiter holding the popped subscriber.
			monitor := NewMonitor(ftesting.NewMockBulk(), mm, config.ServerLimits{PolicyLimit: config.Limit{Burst: 1, Interval: time.Hour}})
			pm := monitor.(*monitorT)
			pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
				return []model.Policy{}, nil
			}

			var mwg sync.WaitGroup
			mwg.Go(func() { _ = monitor.Run(ctx) })
			require.NoError(t, pm.waitStart(ctx))

			policyID := uuid.Must(uuid.NewV4()).String()
			pm.mut.Lock()
			pm.policies[policyID] = policyT{head: makeHead()}
			pm.mut.Unlock()

			subs := make([]Subscription, 2)
			for i := range subs {
				sub, err := monitor.Subscribe(uuid.Must(uuid.NewV4()).String(), policyID, 0)
				require.NoError(t, err)
				defer monitor.Unsubscribe(sub)
				subs[i] = sub
			}

			rId := xid.New().String()
			policy := model.Policy{
				ESDocument:     model.ESDocument{Id: rId, Version: 1, SeqNo: 1},
				PolicyID:       policyID,
				CoordinatorIdx: 1,
				Data:           policyDataDefault,
				RevisionIdx:    1,
			}
			policyData, err := json.Marshal(&policy)
			require.NoError(t, err)
			chHitT <- []es.HitT{{ID: rId, SeqNo: 1, Version: 1, Source: policyData}}

			select {
			case <-subs[0].Output():
			case <-time.After(time.Minute):
				require.Fail(t, "first subscriber was not dispatched")
			}
			synctest.Wait() // the dispatcher holds subs[1], rate waiting

			// Fire events back to back, without waiting for the run loop to settle between them.
			// At most one dispatchPending may be running at any time: overlapping dispatchers can
			// each miss a subscriber the other one holds.
			maxDispatchers := 0
			for range 50 {
				pm.kickLoad()
				runtime.Gosched()
				maxDispatchers = max(maxDispatchers, countDispatchers())
			}
			require.LessOrEqual(t, maxDispatchers, 1, "dispatchPending ran concurrently")

			select {
			case p := <-subs[1].Output():
				require.Equal(t, int64(1), p.Policy.RevisionIdx)
			case <-time.After(2 * time.Hour):
				require.Fail(t, "second subscriber was stranded in pendingQ")
			}

			cancel()
			mwg.Wait()
		})
	}
}

// countDispatchers returns how many goroutines are currently inside (*monitorT).dispatchPending.
func countDispatchers() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		if strings.Contains(g, "(*monitorT).dispatchPending(") {
			n++
		}
	}
	return n
}
