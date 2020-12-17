// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

	"fleet/internal/pkg/model"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/monitor/mock"
	ftesting "fleet/internal/pkg/testing"
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
		PolicyId:           policyId,
		CoordinatorIdx:     1,
		Data:               []byte("{}"),
		RevisionIdx:        1,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		mm.Notify(ctx, []es.HitT{
			{
				Id: rId,
				SeqNo: 1,
				Version: 1,
				Source: policyData,
			},
		})
	}()

	timedout := false
	tm := time.NewTimer(500 * time.Millisecond)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		diff := cmp.Diff(policy, subPolicy)
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
		PolicyId:           policyId,
		CoordinatorIdx:     1,
		Data:               []byte("{}"),
		RevisionIdx:        1,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		mm.Notify(ctx, []es.HitT{
			{
				Id: rId,
				SeqNo: 1,
				Version: 1,
				Source: policyData,
			},
		})
	}()

	gotPolicy := false
	tm := time.NewTimer(500 * time.Millisecond)
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
		PolicyId:           policyId,
		CoordinatorIdx:     0,
		Data:               []byte("{}"),
		RevisionIdx:        2,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		mm.Notify(ctx, []es.HitT{
			{
				Id: rId,
				SeqNo: 1,
				Version: 1,
				Source: policyData,
			},
		})
	}()

	gotPolicy := false
	tm := time.NewTimer(500 * time.Millisecond)
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
		PolicyId:           policyId,
		CoordinatorIdx:     1,
		Data:               []byte("{}"),
		RevisionIdx:        2,
	}

	pm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{policy}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	s, err := monitor.Subscribe(agentId, policyId, 1, 1)
	defer monitor.Unsubscribe(s)
	if err != nil {
		t.Fatal(err)
	}

	timedout := false
	tm := time.NewTimer(500 * time.Millisecond)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		diff := cmp.Diff(policy, subPolicy)
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
