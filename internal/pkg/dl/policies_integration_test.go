// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package dl

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/esboot"
	"fleet/internal/pkg/model"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/xid"
)

func createRandomPolicy(id string, revisionIdx int) model.Policy {
	now := time.Now().UTC()
	return model.Policy{
		PolicyId:           id,
		RevisionIdx:        revisionIdx,
		CoordinatorIdx:     0,
		Data:               "policy",
		DefaultFleetServer: false,
		Timestamp:          now.Format(time.RFC3339),
	}
}

func storeRandomPolicy(ctx context.Context, bulker bulk.Bulk, index string) (model.Policy, error) {
	var rec model.Policy
	id := uuid.Must(uuid.NewV4()).String()
	for i := 1; i < 4; i++ {
		rec = createRandomPolicy(id, i)
		body, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		_, err = bulker.Create(ctx, index, "", body, bulk.WithRefresh())
		if err != nil {
			return nil, err
		}
	}
	return rec, nil
}

func setupPolicies(ctx context.Context, t *testing.T, index string) (bulk.Bulk, map[string]model.Policy) {
	cfg, err := config.LoadFile("../../../fleet-server.yml")
	if err != nil {
		t.Fatal(err)
	}

	cli, bulker, err := bulk.InitES(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	err = esboot.EnsureIndex(ctx, cli, index, es.MappingPolicy)
	if err != nil {
		t.Fatal(err)
	}
	policies := map[string]model.Policy{}
	for i := 0; i < 0; i++ {
		rec, err := storeRandomPolicy(ctx, bulker, index)
		if err != nil {
			t.Fatal(err)
		}
		policies[rec.PolicyId] = rec
	}
	return bulker, policies
}

func TestQueryLatestPolicies(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	// temp index name to avoid collisions with other parallel tests
	index := xid.New().String()
	bulker, recs := setupPolicies(ctx, t, index)

	policies, err := QueryLatestPolicies(ctx, bulker)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]model.Policy{}
	for _, policy := range policies {
		byID[policy.PolicyId] = policy
	}

	diff := cmp.Diff(recs, byID)
	if diff != "" {
		t.Fatal(diff)
	}
}
