// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

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

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor/mock"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestMonitor_NewPolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bulker := ftesting.MockBulk{}
	mm := mock.NewMockIndexMonitor()
	monitor := NewMonitor(bulker, mm, 0)
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

	if err := monitor.(*monitorT).waitStart(ctx); err != nil {
		t.Fatal(err)
	}

	agentId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyId, 0, 0)
	defer monitor.Unsubscribe(s)
	if err != nil {
		t.Fatal(err)
	}

	rId := xid.New().String()
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyId:       policyId,
		CoordinatorIdx: 1,
		Data:           []byte("{}"),
		RevisionIdx:    1,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		mm.Notify(ctx, []es.HitT{
			{
				Id:      rId,
				SeqNo:   1,
				Version: 1,
				Source:  policyData,
			},
		})
	}()

	timedout := false
	tm := time.NewTimer(2 * time.Second)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		diff := cmp.Diff(policy, subPolicy.Policy)
		if diff != "" {
			t.Fatal(diff)
		}
	case <-tm.C:
		timedout = true
	}

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
	if timedout {
		t.Fatal("never got policy update; timed out after 2s")
	}
}

func TestMonitor_SamePolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bulker := ftesting.MockBulk{}
	mm := mock.NewMockIndexMonitor()
	monitor := NewMonitor(bulker, mm, 0)
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

	agentId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyId, 1, 1)
	defer monitor.Unsubscribe(s)
	if err != nil {
		t.Fatal(err)
	}

	rId := xid.New().String()
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyId:       policyId,
		CoordinatorIdx: 1,
		Data:           []byte("{}"),
		RevisionIdx:    1,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		mm.Notify(ctx, []es.HitT{
			{
				Id:      rId,
				SeqNo:   1,
				Version: 1,
				Source:  policyData,
			},
		})
	}()

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
	if gotPolicy {
		t.Fatal("got policy update when it was the same rev/coord idx")
	}
}

func TestMonitor_NewPolicyUncoordinated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bulker := ftesting.MockBulk{}
	mm := mock.NewMockIndexMonitor()
	monitor := NewMonitor(bulker, mm, 0)
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

	agentId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	s, err := monitor.Subscribe(agentId, policyId, 1, 1)
	defer monitor.Unsubscribe(s)
	if err != nil {
		t.Fatal(err)
	}

	rId := xid.New().String()
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyId:       policyId,
		CoordinatorIdx: 0,
		Data:           []byte("{}"),
		RevisionIdx:    2,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		mm.Notify(ctx, []es.HitT{
			{
				Id:      rId,
				SeqNo:   1,
				Version: 1,
				Source:  policyData,
			},
		})
	}()

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
	if gotPolicy {
		t.Fatal("got policy update when it had coordinator_idx set to 0")
	}
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

	bulker := ftesting.MockBulk{}
	mm := mock.NewMockIndexMonitor()
	monitor := NewMonitor(bulker, mm, 0)
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
		PolicyId:       policyId,
		CoordinatorIdx: 1,
		Data:           []byte("{}"),
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

	s, err := monitor.Subscribe(agentId, policyId, 1, 1)
	defer monitor.Unsubscribe(s)
	if err != nil {
		t.Fatal(err)
	}

	timedout := false
	tm := time.NewTimer(2 * time.Second)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		diff := cmp.Diff(policy, subPolicy.Policy)
		if diff != "" {
			t.Fatal(diff)
		}
	case <-tm.C:
		timedout = true
	}

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
	if timedout {
		t.Fatal("never got policy update; timed out after 500ms")
	}
}
