// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package policy

import (
	"context"
	"encoding/json"
	"fmt"
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

func Test_Monitor_cancel_pending(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	chHitT := make(chan []es.HitT, 2)
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
	pm.dispatchCh = make(chan struct{}, 1)

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
		RevisionIdx: 1,
	}
	policyData, err := json.Marshal(&policy)
	require.NoError(t, err)
	policy2 := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:    policyId,
		Data:        policyDataDefault,
		RevisionIdx: 2,
	}
	policyData2, err := json.Marshal(&policy2)
	require.NoError(t, err)

	// Send both revisions to monitor as as seperate hits
	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   1,
		Version: 1,
		Source:  policyData,
	}}
	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   2,
		Version: 1,
		Source:  policyData2,
	}}

	// start monitor
	var merr error
	var mwg sync.WaitGroup
	mwg.Go(func() {
		merr = monitor.Run(ctx)
	})
	err = monitor.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	// subscribe with revision 0
	s, err := monitor.Subscribe(agentId, policyId, 0)
	defer monitor.Unsubscribe(s)
	require.NoError(t, err)

	// This sleep allows the main run to call dispatch
	// but dispatch will not proceed until there is a signal from the dispatchCh
	time.Sleep(100 * time.Millisecond)
	pm.dispatchCh <- struct{}{}

	tm := time.NewTimer(time.Second)
	policies := make([]*ParsedPolicy, 0, 2)
LOOP:
	for {
		select {
		case p := <-s.Output():
			policies = append(policies, p)
		case <-tm.C:
			break LOOP
		}
	}

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
	require.Len(t, policies, 1, "expected to recieve one revision")
	require.Equal(t, policies[0].Policy.RevisionIdx, int64(2))
	ms.AssertExpectations(t)
	mm.AssertExpectations(t)
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

// Test_Monitor_dispatchPending_cancelKick asserts that a cancelled dispatchPending returns its
// subscriber to pendingQ and kicks the run loop only if a replacement dispatch already found
// the queue empty. Otherwise the kick would cancel an active replacement that holds the
// subscriber, which would requeue and kick again in a cancellation loop.
func Test_Monitor_dispatchPending_cancelKick(t *testing.T) {
	for name, tc := range map[string]struct {
		replacementFoundEmptyQueue bool
		expectKick                 bool
	}{
		"replacement found empty queue": {replacementFoundEmptyQueue: true, expectKick: true},
		"replacement has not popped":    {replacementFoundEmptyQueue: false, expectKick: false},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			ctx = testlog.SetLogger(t).WithContext(ctx)

			monitor := NewMonitor(ftesting.NewMockBulk(), mmock.NewMockMonitor(), config.ServerLimits{})
			pm := monitor.(*monitorT)
			pm.log = zerolog.Ctx(ctx).With().Logger()
			if tc.replacementFoundEmptyQueue {
				// The replacement dispatch runs while the cancelled one holds the subscriber.
				pm.beforeRequeue = func() { require.Nil(t, pm.popPending()) }
			}

			policyID := uuid.Must(uuid.NewV4()).String()
			sub := NewSub(policyID, uuid.Must(uuid.NewV4()).String(), 0)
			pm.mut.Lock()
			pm.policies[policyID] = policyT{head: makeHead()}
			pm.pendingQ.pushBack(sub)
			pm.mut.Unlock()

			// The context is already cancelled, so the rate limiter wait fails after
			// the subscriber has been popped from pendingQ.
			cancel()
			pm.dispatchPending(ctx)

			pm.mut.Lock()
			requeued := pm.pendingQ.popFront()
			pm.mut.Unlock()
			require.Same(t, sub, requeued, "subscriber must be returned to pendingQ")

			select {
			case <-pm.deployCh:
				require.True(t, tc.expectKick, "deploy must not be kicked")
			default:
				require.False(t, tc.expectKick, "deploy was not kicked")
			}
		})
	}
}

// Test_Monitor_cancelled_dispatch_does_not_strand_subscriber reproduces the race where a
// cancelled dispatchPending (A) has popped a subscriber but not yet returned it to pendingQ
// when its replacement (B) runs. B finds the queue empty and exits, so the subscriber must be
// delivered by the extra dispatch that A kicks after returning it.
func Test_Monitor_cancelled_dispatch_does_not_strand_subscriber(t *testing.T) {
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
		// Hold the cancelled dispatch right before it returns its subscriber to pendingQ.
		reached := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		pm.beforeRequeue = func() {
			once.Do(func() { close(reached) })
			<-release
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

		// A new event cancels A and starts B. A is held before the push-back, so B pops an empty queue and exits.
		pm.kickLoad()
		<-reached
		synctest.Wait()

		// Let the rate limiter pass so the extra dispatch kicked by A can deliver, then let A push back.
		pm.limit.SetLimit(rate.Inf)
		close(release)

		select {
		case p := <-subs[1].Output():
			require.Equal(t, int64(1), p.Policy.RevisionIdx)
		case <-time.After(time.Minute):
			require.Fail(t, "second subscriber was stranded in pendingQ")
		}

		cancel()
		mwg.Wait()
	})
}

// Test_Monitor_dispatchPending_limiterDeadlineDoesNotKick asserts that a limiter error that is
// not a cancellation (the wait would exceed the context deadline) returns the subscriber to
// pendingQ without kicking when no replacement dispatch missed it.
func Test_Monitor_dispatchPending_limiterDeadlineDoesNotKick(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	monitor := NewMonitor(ftesting.NewMockBulk(), mmock.NewMockMonitor(), config.ServerLimits{PolicyLimit: config.Limit{Burst: 1, Interval: time.Hour}})
	pm := monitor.(*monitorT)
	pm.log = zerolog.Ctx(ctx).With().Logger()
	require.True(t, pm.limit.Allow(), "consume the limiter burst")

	policyID := uuid.Must(uuid.NewV4()).String()
	sub := NewSub(policyID, uuid.Must(uuid.NewV4()).String(), 0)
	pm.mut.Lock()
	pm.policies[policyID] = policyT{head: makeHead()}
	pm.pendingQ.pushBack(sub)
	pm.mut.Unlock()

	pm.dispatchPending(ctx)
	require.NoError(t, ctx.Err(), "context must not be done for this scenario")

	pm.mut.Lock()
	requeued := pm.pendingQ.popFront()
	pm.mut.Unlock()
	require.Same(t, sub, requeued, "subscriber must be returned to pendingQ")

	select {
	case <-pm.deployCh:
		require.Fail(t, "deploy must not be kicked for a non-cancellation limiter error")
	default:
	}
}

// Test_Monitor_requeue_kick_cancels_replacement_before_pop covers the interleaving where the kick
// from a cancelled dispatch A (which requeues after a replacement B found the queue empty)
// cancels replacement C before C has popped. C then pops under a cancelled context and requeues
// without kicking, so the subscribers must be delivered by dispatch D, which A's kick starts.
// The test holds C and D before their first pop and releases them in both orders.
func Test_Monitor_requeue_kick_cancels_replacement_before_pop(t *testing.T) {
	for name, releaseCFirst := range map[string]bool{"release C then D": true, "release D then C": false} {
		t.Run(name, func(t *testing.T) {
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

				monitor := NewMonitor(ftesting.NewMockBulk(), mm, config.ServerLimits{PolicyLimit: config.Limit{Burst: 1, Interval: time.Hour}})
				pm := monitor.(*monitorT)
				pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
					return []model.Policy{}, nil
				}

				// Dispatch ids in start order: 1=A (hit), 2=B (kickLoad), 3=C (subscribe), 4=D (A's kick).
				gates := map[int]chan struct{}{3: make(chan struct{}), 4: make(chan struct{})}
				var gmu sync.Mutex
				n := 0
				pm.beforePop = func() {
					gmu.Lock()
					n++
					g := gates[n]
					gmu.Unlock()
					if g != nil {
						<-g
					}
				}
				reached := make(chan struct{})
				release := make(chan struct{})
				var once sync.Once
				pm.beforeRequeue = func() {
					once.Do(func() { close(reached) })
					<-release
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
				synctest.Wait() // A holds subs[1], rate waiting

				pm.kickLoad() // cancels A (held before requeue); B pops empty
				<-reached
				synctest.Wait()

				// New subscriber needing the policy enqueues S and starts C, held before its pop.
				sub3, err := monitor.Subscribe(uuid.Must(uuid.NewV4()).String(), policyID, 0)
				require.NoError(t, err)
				defer monitor.Unsubscribe(sub3)
				synctest.Wait()

				pm.limit.SetLimit(rate.Inf)
				close(release) // A requeues; kicks if emptyPop; Run cancels C and starts D (held)
				synctest.Wait()

				if releaseCFirst {
					close(gates[3])
					synctest.Wait()
					close(gates[4])
				} else {
					close(gates[4])
					synctest.Wait()
					close(gates[3])
				}

				for i, sub := range []Subscription{subs[1], sub3} {
					select {
					case <-sub.Output():
					case <-time.After(time.Minute):
						require.FailNowf(t, "stranded", "subscriber %d was never dispatched", i)
					}
				}
				gmu.Lock()
				require.Equal(t, 4, n, "A's kick must have started dispatch D")
				gmu.Unlock()
				cancel()
				mwg.Wait()
			})
		})
	}
}
