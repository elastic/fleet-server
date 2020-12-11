// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package dl

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/xid"

	"fleet/internal/pkg/es"
	"fleet/internal/pkg/model"
	ftesting "fleet/internal/pkg/testing"
)

func TestSearchPolicyLeaders(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	// temp index name to avoid collisions with other parallel tests
	index := xid.New().String()
	bulker := setupIndex(ctx, t, index, es.MappingPolicyLeader)

	// insert a policy leaders to search for
	serverId := uuid.Must(uuid.NewV4()).String()
	policyIds := make([]string, 3)
	for i := 0; i < 3; i++ {
		policyId := uuid.Must(uuid.NewV4()).String()
		version := "1.0.0"
		err := TakePolicyLeadership(ctx, bulker, policyId, serverId, version, WithIndexName(index))
		if err != nil {
			t.Fatal(err)
		}
		policyIds[i] = policyId
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

	// temp index name to avoid collisions with other parallel tests
	index := xid.New().String()
	bulker := setupIndex(ctx, t, index, es.MappingPolicyLeader)

	serverId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	version := "1.0.0"
	err := TakePolicyLeadership(ctx, bulker, policyId, serverId, version, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	data, err := bulker.Read(ctx, index, policyId)
	if err != nil {
		t.Fatal(err)
	}
	var leader model.PolicyLeader
	err = json.Unmarshal(data, &leader)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Server.Id != serverId || leader.Server.Version != version {
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

	// temp index name to avoid collisions with other parallel tests
	index := xid.New().String()
	bulker := setupIndex(ctx, t, index, es.MappingPolicyLeader)

	serverId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	version := "1.0.0"
	err := TakePolicyLeadership(ctx, bulker, policyId, serverId, version, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}
	err = ReleasePolicyLeadership(ctx, bulker, policyId, serverId, 30*time.Second, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	data, err := bulker.Read(ctx, index, policyId)
	if err != nil {
		t.Fatal(err)
	}
	var leader model.PolicyLeader
	err = json.Unmarshal(data, &leader)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Server.Id != serverId || leader.Server.Version != version {
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

	// temp index name to avoid collisions with other parallel tests
	index := xid.New().String()
	bulker := setupIndex(ctx, t, index, es.MappingPolicyLeader)

	serverId := uuid.Must(uuid.NewV4()).String()
	policyId := uuid.Must(uuid.NewV4()).String()
	version := "1.0.0"
	err := TakePolicyLeadership(ctx, bulker, policyId, serverId, version, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}
	otherServerId := uuid.Must(uuid.NewV4()).String()
	err = ReleasePolicyLeadership(ctx, bulker, policyId, otherServerId, 30*time.Second, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	data, err := bulker.Read(ctx, index, policyId)
	if err != nil {
		t.Fatal(err)
	}
	var leader model.PolicyLeader
	err = json.Unmarshal(data, &leader)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Server.Id != serverId || leader.Server.Version != version {
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
