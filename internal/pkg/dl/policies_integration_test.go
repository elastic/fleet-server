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

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
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
		Outputs: map[string]map[string]any{
			testDefaultOutput: {
				FiledType: testES,
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]any{},
	}
	return model.Policy{
		PolicyID:           id,
		RevisionIdx:        int64(revisionIdx),
		Data:               &policyData,
		DefaultFleetServer: false,
		Timestamp:          now.Format(time.RFC3339),
	}
}

func storeRandomPolicies(ctx context.Context, bulker bulk.Bulk, index string, count, maxRev int) error {
	ops := make([]bulk.MultiOp, 0, count*maxRev)
	for range count {
		id := uuid.Must(uuid.NewV4()).String()
		for i := 1; i <= maxRev; i++ {
			rec := createRandomPolicy(id, i)
			p, err := json.Marshal(&rec)
			if err != nil {
				return err
			}
			ops = append(ops, bulk.MultiOp{
				Index: index,
				Body:  p,
			})
		}
	}
<<<<<<< HEAD
	_, err := bulker.MIndex(ctx, ops, bulk.WithRefresh())
=======
	items, err := bulker.MIndex(ctx, ops, bulk.WithRefresh())
>>>>>>> e1e4620 (Fix ignored options on Fleet Server bulk writes (#8297))
	if err != nil {
		return err
	}
<<<<<<< HEAD
	return nil
=======
	for i, item := range items {
		if err := es.TranslateError(item.Status, item.Error); err != nil {
			writeErr := fmt.Errorf("write policy fixture %d: %w", i, err)
			return nil, writeErr
		}
	}
	return ids, nil
>>>>>>> e1e4620 (Fix ignored options on Fleet Server bulk writes (#8297))
}

func TestQueryLatestPolicies(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies, bulk.WithFlushThresholdCount(1))

	err := storeRandomPolicies(ctx, bulker, index, 4, 4)
	if err != nil {
		t.Fatal(err)
	}

	var policies []model.Policy
	require.Eventually(t, func() bool {
		policies, err = QueryLatestPolicies(ctx, bulker, WithIndexName(index))
		if err != nil {
			t.Fatal(err)
		}
		return len(policies) == 4
	}, time.Second*2, time.Millisecond*100, "Expected to eventually have 4 policies, found: %d", len(policies))

	for _, policy := range policies {
		if policy.RevisionIdx != 4 {
			t.Errorf("Expected to find revision_idx 4 for policy %s, found %d", policy.PolicyID, policy.RevisionIdx)
		}
	}
}

<<<<<<< HEAD
// TestQueryLatestPolicies400k tests to see if  to see if the latest revision is correctly selected when a lot the revision count is very large
//
//nolint:dupl // test duplication
func TestQueryLatestPolicies400k(t *testing.T) {
	t.Skip("Test flaky, see: https://github.com/elastic/fleet-server/issues/5181")
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies, bulk.WithFlushThresholdCount(1))

	err := storeRandomPolicies(ctx, bulker, index, 4, 100000)
	if err != nil {
		t.Fatal(err)
	}

	var policies []model.Policy
	require.Eventually(t, func() bool {
		var err error
		policies, err = QueryLatestPolicies(ctx, bulker, WithIndexName(index))
		if err != nil {
			t.Fatal(err)
		}
		return len(policies) == 4
	}, time.Second*2, time.Millisecond*100, "Expected to eventually have 4 policies found: %d", len(policies))

	for _, policy := range policies {
		if policy.RevisionIdx != 100000 {
			t.Errorf("Expected to find revision_idx 100000 for policy %s, found %d", policy.PolicyID, policy.RevisionIdx)
		}
	}
}

// TesyQueryLatestPolices11kUnique tests behaviour when 11k unique policies are used, there is a 10k size specification in the aggregation.
//
//nolint:dupl // test duplication
func TestQueryLatestPolicies11kUnique(t *testing.T) {
	t.Skip("Re-enable after policy load issues have been sorted: https://github.com/elastic/fleet-server/issues/3254")
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies, bulk.WithFlushThresholdCount(1))

	err := storeRandomPolicies(ctx, bulker, index, 11000, 2)
	if err != nil {
		t.Fatal(err)
	}

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
=======
func TestQueryLatestPolicies(t *testing.T) {
	const policyCount = 4
	tests := []struct {
		name      string
		revisions int
	}{
		{
			name:      "the latest revisions are visible after one bulk request",
			revisions: 4,
		},
		{
			name:      "the latest revisions are visible after multiple bulk requests",
			revisions: 100_000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := testlog.SetLogger(t).WithContext(t.Context())
			index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies)

			policies := make([][]model.Policy, policyCount)
			for i := range policies {
				policies[i] = make([]model.Policy, tt.revisions)
				for j := range policies[i] {
					policies[i][j].RevisionIdx = int64(j + 1)
				}
			}
			ids, err := storeRandomPolicies(ctx, bulker, index, policies)
			require.NoError(t, err)

			for _, id := range ids {
				policy, err := QueryLatestPolicy(ctx, bulker, id, WithIndexName(index))
				require.NoError(t, err)
				assert.Equal(t, int64(tt.revisions), policy.RevisionIdx, "policy %s", id)
			}
		})
>>>>>>> e1e4620 (Fix ignored options on Fleet Server bulk writes (#8297))
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
		Outputs: map[string]map[string]any{
			"remote": {
				FiledType: testRemoteES,
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]any{},
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
	require.Equal(t, map[string]any{FiledType: testRemoteES}, policy.Data.Outputs["remote"])
}
