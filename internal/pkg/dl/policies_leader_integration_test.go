// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package dl

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/gofrs/uuid"
)

const testVer = "1.0.0"

func TestSearchPolicyLeaders(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPoliciesLeader)

	// insert a policy leaders to search for
	serverID := uuid.Must(uuid.NewV4()).String()
	policyIds := make([]string, 3)
	for i := 0; i < 3; i++ {
		policyID := uuid.Must(uuid.NewV4()).String()
		version := testVer
		err := TakePolicyLeadership(ctx, bulker, policyID, serverID, version, WithIndexName(index))
		if err != nil {
			t.Fatal(err)
		}
		policyIds[i] = policyID
	}

	// possible that a search will not produce 3 directly after write
	// so we try 3 times to ensure
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		leaders, err := SearchPolicyLeaders(ctx, bulker, policyIds, WithIndexName(index))
		if err != nil {
			return err
		}
		if len(leaders) != 3 {
			return fmt.Errorf("must have found 3 leaders: only found %v", len(leaders))
		}
		return nil
	}, ftesting.RetryCount(3))
}

func TestTakePolicyLeadership(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPoliciesLeader)

	serverID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	version := testVer
	err := TakePolicyLeadership(ctx, bulker, policyID, serverID, version, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	data, err := bulker.Read(ctx, index, policyID)
	if err != nil {
		t.Fatal(err)
	}
	var leader model.PolicyLeader
	err = json.Unmarshal(data, &leader)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Server.ID != serverID || leader.Server.Version != version {
		t.Fatal("server.id and server.version should match")
	}
	lt, err := leader.Time()
	if err != nil {
		t.Fatal(err)
	}
	if time.Now().UTC().Sub(lt) >= 5*time.Second {
		t.Fatal("@timestamp should be with in 5 seconds")
	}
}

func TestReleasePolicyLeadership(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPoliciesLeader)

	serverID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	version := testVer
	err := TakePolicyLeadership(ctx, bulker, policyID, serverID, version, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}
	err = ReleasePolicyLeadership(ctx, bulker, policyID, serverID, 30*time.Second, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	data, err := bulker.Read(ctx, index, policyID)
	if err != nil {
		t.Fatal(err)
	}
	var leader model.PolicyLeader
	err = json.Unmarshal(data, &leader)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Server.ID != serverID || leader.Server.Version != version {
		t.Fatal("server.id and server.version should match")
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

func TestReleasePolicyLeadership_NothingIfNotLeader(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPoliciesLeader)

	serverID := uuid.Must(uuid.NewV4()).String()
	policyID := uuid.Must(uuid.NewV4()).String()
	version := testVer
	err := TakePolicyLeadership(ctx, bulker, policyID, serverID, version, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}
	otherServerID := uuid.Must(uuid.NewV4()).String()
	err = ReleasePolicyLeadership(ctx, bulker, policyID, otherServerID, 30*time.Second, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	data, err := bulker.Read(ctx, index, policyID)
	if err != nil {
		t.Fatal(err)
	}
	var leader model.PolicyLeader
	err = json.Unmarshal(data, &leader)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Server.ID != serverID || leader.Server.Version != version {
		t.Fatal("server.id and server.version should match")
	}
	lt, err := leader.Time()
	if err != nil {
		t.Fatal(err)
	}
	diff := time.Now().UTC().Sub(lt).Seconds()
	if diff >= (5 * time.Second).Seconds() {
		t.Fatalf("@timestamp different should less than 5 seconds; instead its %.0f secs", diff)
	}
}
