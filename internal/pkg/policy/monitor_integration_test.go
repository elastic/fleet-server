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

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

var policyBytes = []byte(`{"outputs":{"default":{"type":"elasticsearch"}}}`)

func TestMonitor_Integration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	m := NewMonitor(bulker, im, 0)
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

	agentID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	s, err := m.Subscribe(agentID, policyID, 0, 0)
	defer m.Unsubscribe(s) //nolint:errcheck // defered function
	if err != nil {
		t.Fatal(err)
	}

	policy := model.Policy{
		PolicyID:       policyID,
		CoordinatorIdx: 1,
		Data:           policyBytes,
		RevisionIdx:    1,
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
		if subPolicy.Policy.PolicyID != policyID && subPolicy.Policy.RevisionIdx != 1 && subPolicy.Policy.CoordinatorIdx != 1 {
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
