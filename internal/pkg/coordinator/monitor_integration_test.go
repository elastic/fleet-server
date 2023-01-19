// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestMonitorLeadership(t *testing.T) {
	parentCtx := context.Background()
	bulkCtx, bulkCn := context.WithCancel(parentCtx)
	defer bulkCn()
	ctx, cn := context.WithCancel(parentCtx)
	defer cn()

	// flush bulker on every operation
	bulker := ftesting.SetupBulk(bulkCtx, t, bulk.WithFlushThresholdCount(1))

	serversIndex := ftesting.CleanIndex(ctx, t, bulker, dl.FleetServers)
	policiesIndex := ftesting.CleanIndex(ctx, t, bulker, dl.FleetPolicies)
	leadersIndex := ftesting.CleanIndex(ctx, t, bulker, dl.FleetPoliciesLeader)

	pim, err := monitor.New(policiesIndex, bulker.Client(), bulker.Client())
	if err != nil {
		t.Fatal(err)
	}
	cfg := makeFleetConfig()
	pm := NewMonitor(cfg, "1.0.0", bulker, pim, NewCoordinatorZero)
	pm.(*monitorT).serversIndex = serversIndex
	pm.(*monitorT).leadersIndex = leadersIndex
	pm.(*monitorT).policiesIndex = policiesIndex

	// start with 1 initial policy
	policy1Id := uuid.Must(uuid.NewV4()).String()
	policy1 := model.Policy{
		PolicyID:       policy1Id,
		CoordinatorIdx: 0,
		Data:           []byte("{}"),
		RevisionIdx:    1,
	}
	_, err = dl.CreatePolicy(ctx, bulker, policy1, dl.WithIndexName(policiesIndex))
	if err != nil {
		t.Fatal(err)
	}

	// start the monitors
	g, _ := errgroup.WithContext(context.Background())
	g.Go(func() error {
		err := pim.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		err := pm.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	})

	// wait 500ms to ensure everything is running; then create a new policy
	<-time.After(500 * time.Millisecond)
	policy2Id := uuid.Must(uuid.NewV4()).String()
	policy2 := model.Policy{
		PolicyID:       policy2Id,
		CoordinatorIdx: 0,
		Data:           []byte("{}"),
		RevisionIdx:    1,
	}
	_, err = dl.CreatePolicy(ctx, bulker, policy2, dl.WithIndexName(policiesIndex))
	if err != nil {
		t.Fatal(err)
	}

	// wait 2 seconds so the index monitor notices the new policy
	<-time.After(2 * time.Second)
	ensureServer(ctx, t, bulker, cfg, serversIndex)
	ensureLeadership(ctx, t, bulker, cfg, leadersIndex, policy1Id)
	ensureLeadership(ctx, t, bulker, cfg, leadersIndex, policy2Id)
	ensurePolicy(ctx, t, bulker, policiesIndex, policy1Id, 1, 1)
	ensurePolicy(ctx, t, bulker, policiesIndex, policy2Id, 1, 1)

	// stop the monitors
	cn()
	err = g.Wait()
	require.NoError(t, err)

	// ensure leadership was released
	ensureLeadershipReleased(bulkCtx, t, bulker, cfg, leadersIndex, policy1Id)
	ensureLeadershipReleased(bulkCtx, t, bulker, cfg, leadersIndex, policy2Id)
}

func makeFleetConfig() config.Fleet {
	id := uuid.Must(uuid.NewV4()).String()
	return config.Fleet{
		Agent: config.Agent{
			ID:      id,
			Version: "1.0.0",
		},
		Host: config.Host{
			ID: id,
		},
	}
}

func ensureServer(ctx context.Context, t *testing.T, bulker bulk.Bulk, cfg config.Fleet, index string) {
	t.Helper()
	var srv model.Server
	data, err := bulker.Read(ctx, index, cfg.Agent.ID, bulk.WithRefresh())
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(data, &srv)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Agent.ID != cfg.Agent.ID {
		t.Fatal("agent.id should match from configuration")
	}
}

func ensureLeadership(ctx context.Context, t *testing.T, bulker bulk.Bulk, cfg config.Fleet, index string, policyID string) {
	t.Helper()
	var leader model.PolicyLeader
	data, err := bulker.Read(ctx, index, policyID)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(data, &leader)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Server.ID != cfg.Agent.ID {
		t.Fatal("server.id should match from configuration")
	}
	lt, err := leader.Time()
	if err != nil {
		t.Fatal(err)
	}
	if time.Now().UTC().Sub(lt) >= 5*time.Second {
		t.Fatal("@timestamp should be with in 5 seconds")
	}
}

func ensurePolicy(ctx context.Context, t *testing.T, bulker bulk.Bulk, index string, policyID string, revisionIdx, coordinatorIdx int64) {
	t.Helper()
	policies, err := dl.QueryLatestPolicies(ctx, bulker, dl.WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}
	var found *model.Policy
	for i := range policies {
		p := policies[i]
		if p.PolicyID == policyID {
			found = &p
			break
		}
	}
	if found == nil {
		t.Fatal("policy not found")
	}
	if found.RevisionIdx != revisionIdx {
		t.Fatal("revision_idx does not match")
	}
	if found.CoordinatorIdx != coordinatorIdx {
		t.Fatal("coordinator_idx does not match")
	}
}

func ensureLeadershipReleased(ctx context.Context, t *testing.T, bulker bulk.Bulk, cfg config.Fleet, index string, policyID string) {
	t.Helper()
	var leader model.PolicyLeader
	data, err := bulker.Read(ctx, index, policyID)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(data, &leader)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Server.ID != cfg.Agent.ID {
		t.Fatal("server.id should match from configuration")
	}
	lt, err := leader.Time()
	if err != nil {
		t.Fatal(err)
	}
	diff := time.Now().UTC().Sub(lt).Seconds()
	if diff < (30 * time.Second).Seconds() {
		t.Fatalf("@timestamp different should be more than 30 seconds; instead its %.0f secs", diff)
	}
}
