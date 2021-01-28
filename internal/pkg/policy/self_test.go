// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/gofrs/uuid"
	"github.com/rs/xid"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor/mock"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestSelfMonitor_DefaultPolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Fleet{
		Agent: config.Agent{
			ID: "agent-id",
		},
	}
	reporter := &FakeReporter{}
	bulker := ftesting.MockBulk{}
	mm := mock.NewMockIndexMonitor()
	monitor := NewSelfMonitor(cfg, bulker, mm, "", reporter)
	sm := monitor.(*selfMonitorT)
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status, msg, _ := reporter.Current()
		if status != proto.StateObserved_STARTING {
			return fmt.Errorf("should be reported as starting")
		}
		if msg != "Waiting on default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	policyId := uuid.Must(uuid.NewV4()).String()
	rId := xid.New().String()
	policyContents, err := json.Marshal(&policyData{Inputs: []policyInput{
		{
			Type: "fleet-server",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyId:           policyId,
		CoordinatorIdx:     1,
		Data:               policyContents,
		RevisionIdx:        1,
		DefaultFleetServer: true,
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

	// should now be set to healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status, msg, _ := reporter.Current()
		if status != proto.StateObserved_HEALTHY {
			return fmt.Errorf("should be reported as healthy")
		}
		if msg != "Running on default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	})

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
}

func TestSelfMonitor_DefaultPolicy_Degraded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Fleet{
		Agent: config.Agent{
			ID: "",
		},
	}
	reporter := &FakeReporter{}
	bulker := ftesting.MockBulk{}
	mm := mock.NewMockIndexMonitor()
	monitor := NewSelfMonitor(cfg, bulker, mm, "", reporter)
	sm := monitor.(*selfMonitorT)
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status, msg, _ := reporter.Current()
		if status != proto.StateObserved_STARTING {
			return fmt.Errorf("should be reported as starting")
		}
		if msg != "Waiting on default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	policyId := uuid.Must(uuid.NewV4()).String()
	rId := xid.New().String()
	policyContents, err := json.Marshal(&policyData{Inputs: []policyInput{
		{
			Type: "fleet-server",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyId:           policyId,
		CoordinatorIdx:     1,
		Data:               policyContents,
		RevisionIdx:        1,
		DefaultFleetServer: true,
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

	// should now be set to healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status, msg, _ := reporter.Current()
		if status != proto.StateObserved_DEGRADED {
			return fmt.Errorf("should be reported as healthy")
		}
		if msg != "Running on default policy with Fleet Server integration; missing config fleet.agent.id" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	})

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
}

func TestSelfMonitor_SpecificPolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Fleet{
		Agent: config.Agent{
			ID: "agent-id",
		},
	}
	policyId := uuid.Must(uuid.NewV4()).String()
	reporter := &FakeReporter{}
	bulker := ftesting.MockBulk{}
	mm := mock.NewMockIndexMonitor()
	monitor := NewSelfMonitor(cfg, bulker, mm, policyId, reporter)
	sm := monitor.(*selfMonitorT)
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status, msg, _ := reporter.Current()
		if status != proto.StateObserved_STARTING {
			return fmt.Errorf("should be reported as starting")
		}
		if msg != fmt.Sprintf("Waiting on policy with Fleet Server integration: %s", policyId) {
			return fmt.Errorf("should be matching with specific policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	rId := xid.New().String()
	policyContents, err := json.Marshal(&policyData{Inputs: []policyInput{
		{
			Type: "fleet-server",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyId:           policyId,
		CoordinatorIdx:     1,
		Data:               policyContents,
		RevisionIdx:        1,
		DefaultFleetServer: true,
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

	// should now be set to healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status, msg, _ := reporter.Current()
		if status != proto.StateObserved_HEALTHY {
			return fmt.Errorf("should be reported as healthy")
		}
		if msg != fmt.Sprintf("Running on policy with Fleet Server integration: %s", policyId) {
			return fmt.Errorf("should be matching with specific policy")
		}
		return nil
	})

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
}

func TestSelfMonitor_SpecificPolicy_Degraded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Fleet{
		Agent: config.Agent{
			ID: "",
		},
	}
	policyId := uuid.Must(uuid.NewV4()).String()
	reporter := &FakeReporter{}
	bulker := ftesting.MockBulk{}
	mm := mock.NewMockIndexMonitor()
	monitor := NewSelfMonitor(cfg, bulker, mm, policyId, reporter)
	sm := monitor.(*selfMonitorT)
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		return []model.Policy{}, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status, msg, _ := reporter.Current()
		if status != proto.StateObserved_STARTING {
			return fmt.Errorf("should be reported as starting")
		}
		if msg != fmt.Sprintf("Waiting on policy with Fleet Server integration: %s", policyId) {
			return fmt.Errorf("should be matching with specific policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	rId := xid.New().String()
	policyContents, err := json.Marshal(&policyData{Inputs: []policyInput{
		{
			Type: "fleet-server",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyId:           policyId,
		CoordinatorIdx:     1,
		Data:               policyContents,
		RevisionIdx:        1,
		DefaultFleetServer: true,
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

	// should now be set to healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		status, msg, _ := reporter.Current()
		if status != proto.StateObserved_DEGRADED {
			return fmt.Errorf("should be reported as healthy")
		}
		if msg != fmt.Sprintf("Running on policy with Fleet Server integration: %s; missing config fleet.agent.id", policyId) {
			return fmt.Errorf("should be matching with specific policy")
		}
		return nil
	})

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
}

type FakeReporter struct {
	lock    sync.Mutex
	status  proto.StateObserved_Status
	msg     string
	payload map[string]interface{}
}

func (r *FakeReporter) Status(status proto.StateObserved_Status, message string, payload map[string]interface{}) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.status = status
	r.msg = message
	r.payload = payload
	return nil
}

func (r *FakeReporter) Current() (proto.StateObserved_Status, string, map[string]interface{}) {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.status, r.msg, r.payload
}
