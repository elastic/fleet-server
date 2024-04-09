// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package policy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

var intPolData = model.PolicyData{
	Outputs: map[string]map[string]interface{}{
		"default": {
			"type": "elasticsearch",
		},
	},
}

func TestMonitor_Integration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetPolicies)

	im, err := monitor.New(index, bulker.Client(), bulker.Client())
	if err != nil {
		t.Fatal(err)
	}

	// Start index monitor
	var imerr error
	var imwg sync.WaitGroup
	imwg.Add(1)
	go func() {
		defer imwg.Done()
		imerr = im.Run(ctx)
		if errors.Is(imerr, context.Canceled) {
			imerr = nil
		}
	}()

	m := NewMonitor(bulker, im, config.ServerLimits{})
	pm, ok := m.(*monitorT)
	if !ok {
		t.Fatalf("unable to cast monitor m (type %T) as *monitorT", m)
	}
	pm.policiesIndex = index

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = m.Run(ctx)
		if errors.Is(merr, context.Canceled) {
			merr = nil
		}
	}()
	err = m.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	s, err := m.Subscribe(agentID, policyID, 0)
	defer m.Unsubscribe(s) //nolint:errcheck // defered function
	if err != nil {
		t.Fatal(err)
	}

	policy := model.Policy{
		PolicyID:    policyID,
		Data:        &intPolData,
		RevisionIdx: 1,
	}
	ch := make(chan error, 1)
	go func() {
		_, err := dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
		if err != nil {
			ch <- err
		}
	}()

	timedout := false
	tm := time.NewTimer(3 * time.Second)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		if subPolicy.Policy.PolicyID != policyID && subPolicy.Policy.RevisionIdx != 1 {
			t.Fatal("failed to get the expected updated policy")
		}
	case <-tm.C:
		timedout = true
	}

	cancel()
	imwg.Wait()
	mwg.Wait()
	if imerr != nil {
		t.Fatal(imerr)
	}
	if merr != nil {
		t.Fatal(merr)
	}
	if timedout {
		t.Fatal("never got policy update; timed out after 3s")
	}
	select {
	case err := <-ch:
		t.Fatalf("error creating policy: %v", err)
	default:
	}
}

func TestMonitor_Debounce_Integration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetPolicies)

	im, err := monitor.New(index, bulker.Client(), bulker.Client(), monitor.WithDebounceTime(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	// Start index monitor
	var imerr error
	var imwg sync.WaitGroup
	imwg.Add(1)
	go func() {
		defer imwg.Done()
		imerr = im.Run(ctx)
		if errors.Is(imerr, context.Canceled) {
			imerr = nil
		}
	}()

	m := NewMonitor(bulker, im, config.ServerLimits{})
	pm, ok := m.(*monitorT)
	if !ok {
		t.Fatalf("unable to cast monitor m (type %T) as *monitorT", m)
	}
	pm.policiesIndex = index

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = m.Run(ctx)
		if errors.Is(merr, context.Canceled) {
			merr = nil
		}
	}()
	err = m.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	s, err := m.Subscribe(agentID, policyID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Unsubscribe(s) //nolint:errcheck // defered function

	policy := model.Policy{
		PolicyID:       policyID,
		CoordinatorIdx: 1,
		Data:           &intPolData,
		RevisionIdx:    1,
	}
	ch := make(chan error, 1)
	go func() {
		_, err := dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
		if err != nil {
			ch <- err
		}
		t.Log("added rev 1 policy to index")

		// update the policy twice within debounce time
		err = sleep.WithContext(ctx, time.Millisecond*100)
		if err != nil {
			ch <- err
			return
		}
		policy.RevisionIdx = 2
		_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
		if err != nil {
			ch <- err
			return
		}
		t.Log("added rev 2 policy to index")

		err = sleep.WithContext(ctx, time.Millisecond*100)
		if err != nil {
			ch <- err
			return
		}
		policy.RevisionIdx = 3
		_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
		if err != nil {
			ch <- err
			return
		}
		t.Log("added rev 3 policy to index")

		err = sleep.WithContext(ctx, time.Second)
		if err != nil {
			ch <- err
			return
		}
		policy.RevisionIdx = 4
		_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
		if err != nil {
			ch <- err
			return
		}
		t.Log("added rev 4 policy to index")
	}()

	timedout := false
	tm := time.NewTimer(3 * time.Second)
	var ts time.Time
	select {
	case subPolicy := <-s.Output():
		// first version of the policy should be returned fist
		ts = time.Now()
		tm.Stop()
		t.Log("received initial policy from subsciption")
		if subPolicy.Policy.PolicyID != policyID && subPolicy.Policy.RevisionIdx != 1 && subPolicy.Policy.CoordinatorIdx != 1 {
			t.Fatal("failed to get the expected updated policy")
		}
	case <-tm.C:
		timedout = true
	}

	if timedout {
		t.Fatal("Did not receive initial policy in 3s")
	}

	// Make new subscription to replicate agent checking in again.
	s2, err := m.Subscribe(agentID, policyID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Unsubscribe(s2) //nolint:errcheck // defered function

	tm.Reset(3 * time.Second)
	select {
	case subPolicy := <-s2.Output():
		dur := time.Since(ts)
		tm.Stop()
		t.Log("received second policy from subsciption")
		// check debounce time
		if dur < time.Second {
			t.Fatalf("Expected subscription to take at least 1s to update, time was: %s", dur)
		}
		// 2nd version of policy should be skipped, 3rd should be read.
		if subPolicy.Policy.PolicyID != policyID && subPolicy.Policy.RevisionIdx != 3 && subPolicy.Policy.CoordinatorIdx != 1 {
			t.Fatal("failed to get the expected updated policy")
		}
	case <-tm.C:
		timedout = true

	}

	s3, err := m.Subscribe(agentID, policyID, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Unsubscribe(s3) //nolint:errcheck // defered function

	tm.Reset(3 * time.Second)
	select {
	case subPolicy := <-s3.Output():
		tm.Stop()
		t.Logf("received third policy from subsciption, rev %d", subPolicy.Policy.RevisionIdx)
		// 2nd version of policy should be skipped, 3rd should be read.
		if subPolicy.Policy.PolicyID != policyID && subPolicy.Policy.RevisionIdx != 4 && subPolicy.Policy.CoordinatorIdx != 1 {
			t.Fatal("failed to get the expected updated policy")
		}
	case <-tm.C:
		timedout = true

	}

	cancel()
	imwg.Wait()
	mwg.Wait()
	if imerr != nil {
		t.Fatal(imerr)
	}
	if merr != nil {
		t.Fatal(merr)
	}
	if timedout {
		t.Error("never got policy update; timed out after 3s")
	}
	select {
	case err := <-ch:
		t.Fatalf("error creating policy: %v", err)
	default:
	}
}

func TestMonitor_Revisions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetPolicies)

	im, err := monitor.New(index, bulker.Client(), bulker.Client())
	if err != nil {
		t.Fatal(err)
	}

	// Start index monitor
	var imerr error
	var imwg sync.WaitGroup
	imwg.Add(1)
	go func() {
		defer imwg.Done()
		imerr = im.Run(ctx)
		if errors.Is(imerr, context.Canceled) {
			imerr = nil
		}
	}()

	m := NewMonitor(bulker, im, config.ServerLimits{})
	pm, ok := m.(*monitorT)
	if !ok {
		t.Fatalf("unable to cast monitor m (type %T) as *monitorT", m)
	}
	pm.policiesIndex = index

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = m.Run(ctx)
		if errors.Is(merr, context.Canceled) {
			merr = nil
		}
	}()
	err = m.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()

	policy := model.Policy{
		PolicyID:       policyID,
		CoordinatorIdx: 1,
		Data:           &intPolData,
		RevisionIdx:    1,
	}
	_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	policy.RevisionIdx = 2
	_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	s, err := m.Subscribe(agentID, policyID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Unsubscribe(s) //nolint:errcheck // defered function

	agent2 := uuid.Must(uuid.NewV4()).String()
	s2, err := m.Subscribe(agent2, policyID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Unsubscribe(s2) //nolint:errcheck // defered function

	policy.RevisionIdx = 3
	_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	// policy should be ignored as coordinator_idx is 0
	policy.RevisionIdx = 4
	policy.CoordinatorIdx = 0
	_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	tm := time.NewTimer(3 * time.Second)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		if subPolicy.Policy.PolicyID != policyID && subPolicy.Policy.RevisionIdx != 3 && subPolicy.Policy.CoordinatorIdx != 1 {
			t.Fatalf("failed to get the expected updated policy, policy revision: %d", subPolicy.Policy.RevisionIdx)
		}
	case <-tm.C:
		t.Fatal("Did not receive initial policy in 3s")
	}

	tm.Reset(3 * time.Second)
	select {
	case subPolicy := <-s2.Output():
		tm.Stop()
		if subPolicy.Policy.PolicyID != policyID && subPolicy.Policy.RevisionIdx != 3 && subPolicy.Policy.CoordinatorIdx != 1 {
			t.Fatalf("failed to get the expected updated policy, policy revision: %d", subPolicy.Policy.RevisionIdx)
		}
	case <-tm.C:
		t.Fatal("Did not receive initial policy in 3s")
	}

	cancel()
	imwg.Wait()
	mwg.Wait()
	if imerr != nil {
		t.Fatal(imerr)
	}
	if merr != nil {
		t.Fatal(merr)
	}
}

func TestMonitor_KickDeploy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetPolicies)

	im, err := monitor.New(index, bulker.Client(), bulker.Client())
	if err != nil {
		t.Fatal(err)
	}

	// Start index monitor
	var imerr error
	var imwg sync.WaitGroup
	imwg.Add(1)
	go func() {
		defer imwg.Done()
		imerr = im.Run(ctx)
		if errors.Is(imerr, context.Canceled) {
			imerr = nil
		}
	}()

	m := NewMonitor(bulker, im, config.ServerLimits{})
	pm, ok := m.(*monitorT)
	if !ok {
		t.Fatalf("unable to cast monitor m (type %T) as *monitorT", m)
	}
	pm.policiesIndex = index

	var merr error
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		merr = m.Run(ctx)
		if errors.Is(merr, context.Canceled) {
			merr = nil
		}
	}()
	err = m.(*monitorT).waitStart(ctx)
	require.NoError(t, err)

	agentID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()

	policy := model.Policy{
		PolicyID:       policyID,
		CoordinatorIdx: 1,
		Data:           &intPolData,
		RevisionIdx:    1,
	}
	_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	policy.RevisionIdx = 2
	_, err = dl.CreatePolicy(ctx, bulker, policy, dl.WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	s, err := m.Subscribe(agentID, policyID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Unsubscribe(s) //nolint:errcheck // defered function

	// Force a new policy load so that the kickLoad() func runs
	s2, err := m.Subscribe("test", "test", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	m.Unsubscribe(s2) //nolint:errcheck // test

	tm := time.NewTimer(3 * time.Second)
	select {
	case subPolicy := <-s.Output():
		tm.Stop()
		if subPolicy.Policy.PolicyID != policyID && subPolicy.Policy.RevisionIdx != 2 && subPolicy.Policy.CoordinatorIdx != 1 {
			t.Fatalf("failed to get the expected updated policy, policy revision: %d", subPolicy.Policy.RevisionIdx)
		}
	case <-tm.C:
		t.Fatal("Did not receive initial policy in 3s")
	}

	cancel()
	imwg.Wait()
	mwg.Wait()
	if imerr != nil {
		t.Fatal(imerr)
	}
	if merr != nil {
		t.Fatal(merr)
	}
}
