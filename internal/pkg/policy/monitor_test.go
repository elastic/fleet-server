// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package policy

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/xid"
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
	Outputs: map[string]map[string]interface{}{
		"default": map[string]interface{}{
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
	}, {
		name:  "no limit",
		cfg:   config.ServerLimits{PolicyThrottle: time.Second},
		burst: 1,
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
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	err := monitor.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentId := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyID, 0, 0)
	defer monitor.Unsubscribe(s)
	require.NoError(t, err)

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
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	err := monitor.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyId, 1, 1)
	defer monitor.Unsubscribe(s)
	require.NoError(t, err)

	rId := xid.New().String()
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:       policyId,
		CoordinatorIdx: 1,
		Data:           policyDataDefault,
		RevisionIdx:    1,
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
	require.False(t, gotPolicy, "got policy update when it was the same rev/coord idx")
	ms.AssertExpectations(t)
	mm.AssertExpectations(t)
}

func TestMonitor_NewPolicyUncoordinated(t *testing.T) {
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
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	err := monitor.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyId, 1, 1)
	defer monitor.Unsubscribe(s)
	require.NoError(t, err)

	rId := xid.New().String()
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:       policyId,
		CoordinatorIdx: 0,
		Data:           policyDataDefault,
		RevisionIdx:    2,
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
	require.False(t, gotPolicy, "got policy update when it had coordinator_idx set to 0")
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
		PolicyID:       policyId,
		CoordinatorIdx: 1,
		Data:           policyDataDefault,
		RevisionIdx:    2,
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

	s, err := monitor.Subscribe(agentId, policyId, 1, 1)
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

func Test_Monitor_Limit_Delay(t *testing.T) {
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

	monitor := NewMonitor(bulker, mm, config.ServerLimits{PolicyLimit: config.Limit{Burst: 1, Interval: time.Millisecond * 50}})
	pm := monitor.(*monitorT)
	pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	err := monitor.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentId := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyID, 0, 0)
	defer monitor.Unsubscribe(s)
	require.NoError(t, err)

	agentId = uuid.Must(uuid.NewV4()).String()
	policyID2 := uuid.Must(uuid.NewV4()).String()
	s2, err := monitor.Subscribe(agentId, policyID, 0, 0)
	defer monitor.Unsubscribe(s2)
	require.NoError(t, err)

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

	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   1,
		Version: 1,
		Source:  policyData,
	}}

	policy2 := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:       policyID2,
		CoordinatorIdx: 1,
		Data:           policyDataDefault,
		RevisionIdx:    1,
	}
	policyData, err = json.Marshal(&policy2)
	require.NoError(t, err)
	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   1,
		Version: 1,
		Source:  policyData,
	}}

	timedout := false
	tm := time.NewTimer(2 * time.Second)
	var ts1, ts2 time.Time
LOOP:
	for {
		select {
		case subPolicy := <-s.Output():
			ts1 = time.Now().UTC()
			if !ts2.IsZero() {
				tm.Stop()
				break LOOP
			}
			diff := cmp.Diff(policy, subPolicy.Policy)
			require.Empty(t, diff)
		case subPolicy := <-s2.Output():
			ts2 = time.Now().UTC()
			if !ts1.IsZero() {
				tm.Stop()
				break LOOP
			}
			diff := cmp.Diff(policy2, subPolicy.Policy)
			require.Empty(t, diff)
		case <-tm.C:
			timedout = true
			break LOOP
		}
	}

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
	require.False(t, timedout, "never got policy update; timed out after 2s")
	d := ts2.Sub(ts1)
	if ts1.After(ts2) {
		d *= -1
	}
	assert.LessOrEqual(t, 50*time.Millisecond, d, "Expected limiter delay to be at least 50ms")
	ms.AssertExpectations(t)
	mm.AssertExpectations(t)
}
