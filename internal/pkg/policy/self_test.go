// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/gofrs/uuid"
	"github.com/rs/xid"
	"github.com/stretchr/testify/mock"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	mmock "github.com/elastic/fleet-server/v7/internal/pkg/monitor/mock"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
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

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()
	emptyMap := make(map[string]string)
	bulker.On("GetRemoteOutputErrorMap").Return(emptyMap)
	emptyBulkerMap := make(map[string]bulk.Bulk)
	bulker.On("GetBulkerMap").Return(emptyBulkerMap)

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

	if err := monitor.(*selfMonitorT).waitStart(ctx); err != nil {
		t.Fatal(err)
	}

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != "Waiting on default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	policyID := uuid.Must(uuid.NewV4()).String()
	rId := xid.New().String()
	pData := model.PolicyData{Inputs: []map[string]interface{}{}}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        1,
		DefaultFleetServer: true,
	}
	p, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   1,
		Version: 1,
		Source:  p,
	}}

	// should still be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != "Waiting on fleet-server input to be added to default policy" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	})

	rId = xid.New().String()
	pData = model.PolicyData{Inputs: []map[string]interface{}{
		{
			"type": "fleet-server",
		},
	}}
	policy = model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        2,
		DefaultFleetServer: true,
	}
	p, err = json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   2,
		Version: 1,
		Source:  p,
	}}

	// should now be set to healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateHealthy {
			return fmt.Errorf("should be reported as healthy; instead its %s", state)
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

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()

	emptyMap := make(map[string]string)
	bulker.On("GetRemoteOutputErrorMap").Return(emptyMap)
	emptyBulkerMap := make(map[string]bulk.Bulk)
	bulker.On("GetBulkerMap").Return(emptyBulkerMap)

	monitor := NewSelfMonitor(cfg, bulker, mm, "", reporter)
	sm := monitor.(*selfMonitorT)
	sm.checkTime = 100 * time.Millisecond

	var policyLock sync.Mutex
	var policyResult []model.Policy
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		policyLock.Lock()
		defer policyLock.Unlock()
		return policyResult, nil
	}

	var tokenLock sync.Mutex
	var tokenResult []model.EnrollmentAPIKey
	sm.enrollmentTokenF = func(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentAPIKey, error) {
		tokenLock.Lock()
		defer tokenLock.Unlock()
		return tokenResult, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	if err := monitor.(*selfMonitorT).waitStart(ctx); err != nil {
		t.Fatal(err)
	}

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != "Waiting on default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	policyID := uuid.Must(uuid.NewV4()).String()
	rId := xid.New().String()
	pData := model.PolicyData{Inputs: []map[string]interface{}{
		{
			"type": "fleet-server",
		},
	}}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        1,
		DefaultFleetServer: true,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		chHitT <- []es.HitT{{
			ID:      rId,
			SeqNo:   1,
			Version: 1,
			Source:  policyData,
		}}
		policyLock.Lock()
		defer policyLock.Unlock()
		policyResult = append(policyResult, policy)
	}()

	// should be set to starting because of missing active enrollment keys
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != "Waiting on active enrollment keys to be created in default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	// add an active token
	activeToken := model.EnrollmentAPIKey{
		ESDocument: model.ESDocument{
			Id: xid.New().String(),
		},
		Active:   true,
		APIKey:   "d2JndlFIWUJJUVVxWDVia2NJTV86X0d6ZmljZGNTc1d4R1otbklrZFFRZw==",
		APIKeyID: xid.New().String(),
		Name:     "Active",
		PolicyID: policyID,
	}
	tokenLock.Lock()
	tokenResult = append(tokenResult, activeToken)
	tokenLock.Unlock()

	// should now be set to degraded
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, payload := reporter.Current()
		if state != client.UnitStateDegraded {
			return fmt.Errorf("should be reported as degraded; instead its %s", state)
		}
		if msg != "Running on default policy with Fleet Server integration; missing config fleet.agent.id (expected during bootstrap process)" {
			return fmt.Errorf("should be matching with default policy")
		}
		if payload == nil {
			return fmt.Errorf("payload should not be nil")
		}
		token, set := payload["enrollment_token"]
		if !set {
			return fmt.Errorf("payload should have enrollment-token set")
		}
		if token != activeToken.APIKey {
			return fmt.Errorf("enrollment_token value is incorrect")
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
	policyID := uuid.Must(uuid.NewV4()).String()
	reporter := &FakeReporter{}

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()
	emptyMap := make(map[string]string)
	bulker.On("GetRemoteOutputErrorMap").Return(emptyMap)
	emptyBulkerMap := make(map[string]bulk.Bulk)
	bulker.On("GetBulkerMap").Return(emptyBulkerMap)

	monitor := NewSelfMonitor(cfg, bulker, mm, policyID, reporter)
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

	if err := monitor.(*selfMonitorT).waitStart(ctx); err != nil {
		t.Fatal(err)
	}

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != fmt.Sprintf("Waiting on policy with Fleet Server integration: %s", policyID) {
			return fmt.Errorf("should be matching with specific policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	rId := xid.New().String()
	pData := model.PolicyData{Inputs: []map[string]interface{}{}}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        2,
		DefaultFleetServer: true,
	}
	p, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   1,
		Version: 1,
		Source:  p,
	}}

	// should still be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != fmt.Sprintf("Waiting on fleet-server input to be added to policy: %s", policyID) {
			return fmt.Errorf("should be matching with specific policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	rId = xid.New().String()
	pData = model.PolicyData{Inputs: []map[string]interface{}{
		{
			"type": "fleet-server",
		},
	}}
	policy = model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   2,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        1,
		DefaultFleetServer: true,
	}
	p, err = json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	chHitT <- []es.HitT{{
		ID:      rId,
		SeqNo:   2,
		Version: 1,
		Source:  p,
	}}

	// should now be set to healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateHealthy {
			return fmt.Errorf("should be reported as healthy; instead its %s", state)
		}
		if msg != fmt.Sprintf("Running on policy with Fleet Server integration: %s", policyID) {
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
	policyID := uuid.Must(uuid.NewV4()).String()
	reporter := &FakeReporter{}

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()
	emptyMap := make(map[string]string)
	bulker.On("GetRemoteOutputErrorMap").Return(emptyMap)
	emptyBulkerMap := make(map[string]bulk.Bulk)
	bulker.On("GetBulkerMap").Return(emptyBulkerMap)

	monitor := NewSelfMonitor(cfg, bulker, mm, policyID, reporter)
	sm := monitor.(*selfMonitorT)
	sm.checkTime = 100 * time.Millisecond

	var policyLock sync.Mutex
	var policyResult []model.Policy
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		policyLock.Lock()
		defer policyLock.Unlock()
		return policyResult, nil
	}

	var tokenLock sync.Mutex
	var tokenResult []model.EnrollmentAPIKey
	sm.enrollmentTokenF = func(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentAPIKey, error) {
		tokenLock.Lock()
		defer tokenLock.Unlock()
		return tokenResult, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	if err := monitor.(*selfMonitorT).waitStart(ctx); err != nil {
		t.Fatal(err)
	}

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != fmt.Sprintf("Waiting on policy with Fleet Server integration: %s", policyID) {
			return fmt.Errorf("should be matching with specific policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	rId := xid.New().String()
	pData := model.PolicyData{Inputs: []map[string]interface{}{
		{
			"type": "fleet-server",
		},
	}}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        1,
		DefaultFleetServer: true,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		chHitT <- []es.HitT{{
			ID:      rId,
			SeqNo:   1,
			Version: 1,
			Source:  policyData,
		}}
		policyLock.Lock()
		defer policyLock.Unlock()
		policyResult = append(policyResult, policy)
	}()

	// should be set to starting because of missing active enrollment keys
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != fmt.Sprintf("Waiting on active enrollment keys to be created in policy with Fleet Server integration: %s", policyID) {
			return fmt.Errorf("should be matching with specific policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	// add an active token
	activeToken := model.EnrollmentAPIKey{
		ESDocument: model.ESDocument{
			Id: xid.New().String(),
		},
		Active:   true,
		APIKey:   "d2JndlFIWUJJUVVxWDVia2NJTV86X0d6ZmljZGNTc1d4R1otbklrZFFRZw==",
		APIKeyID: xid.New().String(),
		Name:     "Active",
		PolicyID: policyID,
	}
	tokenLock.Lock()
	tokenResult = append(tokenResult, activeToken)
	tokenLock.Unlock()

	// should now be set to degraded
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, payload := reporter.Current()
		if state != client.UnitStateDegraded {
			return fmt.Errorf("should be reported as degraded; instead its %s", state)
		}
		if msg != fmt.Sprintf("Running on policy with Fleet Server integration: %s; missing config fleet.agent.id (expected during bootstrap process)", policyID) {
			return fmt.Errorf("should be matching with specific policy")
		}
		if payload == nil {
			return fmt.Errorf("payload should not be nil")
		}
		token, set := payload["enrollment_token"]
		if !set {
			return fmt.Errorf("payload should have enrollment-token set")
		}
		if token != activeToken.APIKey {
			return fmt.Errorf("enrollment_token value is incorrect")
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
	state   client.UnitState
	msg     string
	payload map[string]interface{}
}

func (r *FakeReporter) UpdateState(state client.UnitState, message string, payload map[string]interface{}) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.state = state
	r.msg = message
	r.payload = payload
	return nil
}

func (r *FakeReporter) Current() (client.UnitState, string, map[string]interface{}) {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.state, r.msg, r.payload
}
func TestSelfMonitor_RemoteOutput_Degraded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Fleet{
		Agent: config.Agent{
			ID: "agent-id",
		},
	}
	reporter := &FakeReporter{}

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()

	errorMap := make(map[string]string)
	errorMap["remote output"] = "error connecting to remote output"
	bulker.On("GetRemoteOutputErrorMap").Return(errorMap)
	emptyBulkerMap := make(map[string]bulk.Bulk)
	bulker.On("GetBulkerMap").Return(emptyBulkerMap)

	monitor := NewSelfMonitor(cfg, bulker, mm, "", reporter)
	sm := monitor.(*selfMonitorT)
	sm.checkTime = 100 * time.Millisecond

	var policyLock sync.Mutex
	var policyResult []model.Policy
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		policyLock.Lock()
		defer policyLock.Unlock()
		return policyResult, nil
	}

	var tokenLock sync.Mutex
	var tokenResult []model.EnrollmentAPIKey
	sm.enrollmentTokenF = func(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentAPIKey, error) {
		tokenLock.Lock()
		defer tokenLock.Unlock()
		return tokenResult, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	if err := monitor.(*selfMonitorT).waitStart(ctx); err != nil {
		t.Fatal(err)
	}

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != "Waiting on default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	policyID := uuid.Must(uuid.NewV4()).String()
	rId := xid.New().String()
	pData := model.PolicyData{Inputs: []map[string]interface{}{
		{
			"type": "fleet-server",
		},
	}}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        1,
		DefaultFleetServer: true,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		chHitT <- []es.HitT{{
			ID:      rId,
			SeqNo:   1,
			Version: 1,
			Source:  policyData,
		}}
		policyLock.Lock()
		defer policyLock.Unlock()
		policyResult = append(policyResult, policy)
	}()

	// should be set to degraded because of remote output error
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateDegraded {
			return fmt.Errorf("should be reported as degraded; instead its %s", state)
		}
		if msg != "Could not connect to remote ES output" {
			return fmt.Errorf("expected remote ES connection error")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
}

func TestSelfMonitor_RemoteOutput_Back_To_Healthy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Fleet{
		Agent: config.Agent{
			ID: "agent-id",
		},
	}
	reporter := &FakeReporter{}

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()

	errorMap := make(map[string]string)
	errorMap["remote output"] = "error connecting to remote output"
	bulker.On("GetRemoteOutputErrorMap").Return(errorMap).Once()

	// clear error
	emptyMap := make(map[string]string)
	bulker.On("GetRemoteOutputErrorMap").Return(emptyMap).Once()

	emptyBulkerMap := make(map[string]bulk.Bulk)
	bulker.On("GetBulkerMap").Return(emptyBulkerMap)

	monitor := NewSelfMonitor(cfg, bulker, mm, "", reporter)
	sm := monitor.(*selfMonitorT)
	sm.checkTime = 100 * time.Millisecond

	var policyLock sync.Mutex
	var policyResult []model.Policy
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		policyLock.Lock()
		defer policyLock.Unlock()
		return policyResult, nil
	}

	var tokenLock sync.Mutex
	var tokenResult []model.EnrollmentAPIKey
	sm.enrollmentTokenF = func(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentAPIKey, error) {
		tokenLock.Lock()
		defer tokenLock.Unlock()
		return tokenResult, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	if err := monitor.(*selfMonitorT).waitStart(ctx); err != nil {
		t.Fatal(err)
	}

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != "Waiting on default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	policyID := uuid.Must(uuid.NewV4()).String()
	rId := xid.New().String()
	pData := model.PolicyData{Inputs: []map[string]interface{}{
		{
			"type": "fleet-server",
		},
	}}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        1,
		DefaultFleetServer: true,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		chHitT <- []es.HitT{{
			ID:      rId,
			SeqNo:   1,
			Version: 1,
			Source:  policyData,
		}}
		policyLock.Lock()
		defer policyLock.Unlock()
		policyResult = append(policyResult, policy)
	}()

	// should now be set to healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateHealthy {
			return fmt.Errorf("should be reported as healthy; instead its %s", state)
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

func TestSelfMonitor_RemoteOutput_Ping_Degraded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Fleet{
		Agent: config.Agent{
			ID: "agent-id",
		},
	}
	reporter := &FakeReporter{}

	chHitT := make(chan []es.HitT, 1)
	defer close(chHitT)
	ms := mmock.NewMockSubscription()
	ms.On("Output").Return((<-chan []es.HitT)(chHitT))
	mm := mmock.NewMockMonitor()
	mm.On("Subscribe").Return(ms).Once()
	mm.On("Unsubscribe", mock.Anything).Return().Once()
	bulker := ftesting.NewMockBulk()

	emptyMap := make(map[string]string)
	bulker.On("GetRemoteOutputErrorMap").Return(emptyMap)

	bulkerMap := make(map[string]bulk.Bulk)
	outputBulker := ftesting.NewMockBulk()
	mockES, mocktrans := esutil.MockESClient(t)

	mocktrans.Response = &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       nil,
	}

	outputBulker.On("Client").Return(mockES)
	bulkerMap["output1"] = outputBulker
	bulker.On("GetBulkerMap").Return(bulkerMap)

	monitor := NewSelfMonitor(cfg, bulker, mm, "", reporter)
	sm := monitor.(*selfMonitorT)
	sm.checkTime = 100 * time.Millisecond

	var policyLock sync.Mutex
	var policyResult []model.Policy
	sm.policyF = func(ctx context.Context, bulker bulk.Bulk, opt ...dl.Option) ([]model.Policy, error) {
		policyLock.Lock()
		defer policyLock.Unlock()
		return policyResult, nil
	}

	var tokenLock sync.Mutex
	var tokenResult []model.EnrollmentAPIKey
	sm.enrollmentTokenF = func(ctx context.Context, bulker bulk.Bulk, policyID string) ([]model.EnrollmentAPIKey, error) {
		tokenLock.Lock()
		defer tokenLock.Unlock()
		return tokenResult, nil
	}

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = monitor.Run(ctx)
	}()

	if err := monitor.(*selfMonitorT).waitStart(ctx); err != nil {
		t.Fatal(err)
	}

	// should be set to starting
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateStarting {
			return fmt.Errorf("should be reported as starting; instead its %s", state)
		}
		if msg != "Waiting on default policy with Fleet Server integration" {
			return fmt.Errorf("should be matching with default policy")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	policyID := uuid.Must(uuid.NewV4()).String()
	rId := xid.New().String()
	pData := model.PolicyData{Inputs: []map[string]interface{}{
		{
			"type": "fleet-server",
		},
	}}
	policy := model.Policy{
		ESDocument: model.ESDocument{
			Id:      rId,
			Version: 1,
			SeqNo:   1,
		},
		PolicyID:           policyID,
		CoordinatorIdx:     1,
		Data:               &pData,
		RevisionIdx:        1,
		DefaultFleetServer: true,
	}
	policyData, err := json.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		chHitT <- []es.HitT{{
			ID:      rId,
			SeqNo:   1,
			Version: 1,
			Source:  policyData,
		}}
		policyLock.Lock()
		defer policyLock.Unlock()
		policyResult = append(policyResult, policy)
	}()

	// should be set to degraded because of remote output error
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state, msg, _ := reporter.Current()
		if state != client.UnitStateDegraded {
			return fmt.Errorf("should be reported as degraded; instead its %s", state)
		}
		if msg != "Could not connect to remote ES output: output1, status code: 500" {
			return fmt.Errorf("expected remote ES error")
		}
		return nil
	}, ftesting.RetrySleep(1*time.Second))

	cancel()
	mwg.Wait()
	if merr != nil && merr != context.Canceled {
		t.Fatal(merr)
	}
}
