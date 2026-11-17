// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package dl

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

const (
	testDefaultOutput = "default"
	testRemoteES      = "remote_elasticsearch"
)

func createRandomPolicy(id string, revisionIdx int) model.Policy {
	now := time.Now().UTC()
	var policyData = model.PolicyData{
<<<<<<< HEAD
		Outputs: map[string]map[string]interface{}{
			"default": {
				"type": "elasticsearch",
=======
		Outputs: map[string]map[string]any{
			testDefaultOutput: {
				FiledType: testES,
>>>>>>> 8de91f1 (Fix Elasticsearch circuit breaker errors when loading policies (#8223))
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
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

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
<<<<<<< HEAD
	byID := map[string]model.Policy{}
=======

	var policies []model.Policy
	require.Eventually(t, func() bool {
		var err error
		policies, err = QueryLatestPolicies(ctx, bulker, WithIndexName(index))
		if err != nil {
			t.Fatal(err)
		}
		return len(policies) == 4
	}, time.Second*2, time.Millisecond*100, "Expected to eventually have 4 policies found: %d", len(policies))

>>>>>>> 8de91f1 (Fix Elasticsearch circuit breaker errors when loading policies (#8223))
	for _, policy := range policies {
		byID[policy.PolicyID] = policy
	}

<<<<<<< HEAD
	diff := cmp.Diff(recs, byID)
	if diff != "" {
		t.Fatal(diff)
=======
	var policies []model.Policy
	require.Eventually(t, func() bool {
		var err error
		policies, err = QueryLatestPolicies(ctx, bulker, WithIndexName(index))
		if err != nil {
			t.Fatal(err)
		}
		return len(policies) != 11000
	}, time.Second*2, time.Millisecond*100, "Expected to eventually have 11000 policies found: %d", len(policies))

	for _, policy := range policies {
		if policy.RevisionIdx != 2 {
			t.Errorf("Expected to find revision_idx 1 for policy %s, found %d", policy.PolicyID, policy.RevisionIdx)
		}
>>>>>>> 8de91f1 (Fix Elasticsearch circuit breaker errors when loading policies (#8223))
	}
}

func TestQueryLatestPoliciesByIDIntegration(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies)

	// Create 2 policies with 3 revisions each.
	ids := []string{uuid.Must(uuid.NewV4()).String(), uuid.Must(uuid.NewV4()).String()}
	for _, id := range ids {
		for rev := 1; rev <= 3; rev++ {
			_, err := CreatePolicy(ctx, bulker, createRandomPolicy(id, rev), WithIndexName(index))
			require.NoError(t, err)
		}
	}

	policies, err := QueryLatestPoliciesByID(ctx, bulker, []string{ids[0], "missing", ids[1]}, WithIndexName(index))
	require.NoError(t, err)

	require.Len(t, policies, 2, "the policy that does not exist is not in the result")
	for i, policy := range policies {
		require.Equal(t, ids[i], policy.PolicyID)
		require.Equal(t, int64(3), policy.RevisionIdx, "the latest revision of policy %s", ids[i])
	}
}

func TestCreatePolicy(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

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
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies)

	now := time.Now().UTC()
	var policyData = model.PolicyData{
		Outputs: map[string]map[string]interface{}{
			"remote": {
				FiledType: testRemoteES,
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
<<<<<<< HEAD
	require.Equal(t, map[string]interface{}{"type": "remote_elasticsearch"}, policy.Data.Outputs["remote"])
=======
	require.Equal(t, map[string]any{FiledType: testRemoteES}, policy.Data.Outputs["remote"])
>>>>>>> 8de91f1 (Fix Elasticsearch circuit breaker errors when loading policies (#8223))
}
