// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package dl

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func createRandomPolicy(id string, revisionIdx int) model.Policy {
	now := time.Now().UTC()
	var policyData = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]interface{}{},
	}
	return model.Policy{
		PolicyID:           id,
		RevisionIdx:        int64(revisionIdx),
		Data:               &policyData,
		DefaultFleetServer: false,
		Timestamp:          now.Format(time.RFC3339),
	}
}

func storeRandomPolicy(ctx context.Context, bulker bulk.Bulk, index string) (model.Policy, error) {
	var rec model.Policy
	id := uuid.Must(uuid.NewV4()).String()
	for i := 1; i < 4; i++ {
		rec = createRandomPolicy(id, i)
		_, err := CreatePolicy(ctx, bulker, rec, WithIndexName(index))
		if err != nil {
			return model.Policy{}, err
		}
	}
	return rec, nil
}

func TestQueryLatestPolicies(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies)

	recs := map[string]model.Policy{}
	for i := 0; i < 0; i++ {
		rec, err := storeRandomPolicy(ctx, bulker, index)
		if err != nil {
			t.Fatal(err)
		}
		recs[rec.PolicyID] = rec
	}

	policies, err := QueryLatestPolicies(ctx, bulker, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]model.Policy{}
	for _, policy := range policies {
		byID[policy.PolicyID] = policy
	}

	diff := cmp.Diff(recs, byID)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestCreatePolicy(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies)

	policyID := uuid.Must(uuid.NewV4()).String()
	p := createRandomPolicy(policyID, 1)
	id, err := CreatePolicy(ctx, bulker, p, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	_, err = bulker.Read(ctx, index, id)
	if err != nil {
		t.Fatal(err)
	}
}

func TestQueryOutputFromPolicy(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies)

	now := time.Now().UTC()
	var policyData = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"remote": {
				"type": "remote_elasticsearch",
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]interface{}{},
	}
	rec := model.Policy{
		PolicyID:           "policy1",
		RevisionIdx:        1,
		CoordinatorIdx:     0,
		Data:               &policyData,
		DefaultFleetServer: false,
		Timestamp:          now.Format(time.RFC3339),
	}
	_, err := CreatePolicy(ctx, bulker, rec, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	policy, err := QueryOutputFromPolicy(ctx, bulker, "remote", WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, map[string]interface{}{"type": "remote_elasticsearch"}, policy.Data.Outputs["remote"])
}
