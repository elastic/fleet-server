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
	_, err := bulker.MIndex(ctx, ops, bulk.WithRefresh())
	if err != nil {
		return err
	}
	return nil
}

//nolint:dupl // test duplication
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

// TestQueryLatestPolicies400k tests to see if  to see if the latest revision is correctly selected when a lot the revision count is very large
//
//nolint:dupl // test duplication
func TestQueryLatestPolicies400k(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies, bulk.WithFlushThresholdCount(1))

	err := storeRandomPolicies(ctx, bulker, index, 4, 100000)
	if err != nil {
		t.Fatal(err)
	}

	var policies []model.Policy
	require.Eventually(t, func() bool {
		policies, err := QueryLatestPolicies(ctx, bulker, WithIndexName(index))
		if err != nil {
			t.Fatal(err)
		}
		return len(policies) == 4
	}, time.Second*2, time.Millisecond*100, "Expected to eventuually have 4 policies found: %d", len(policies))

	for _, policy := range policies {
		if policy.RevisionIdx != 100000 {
			t.Errorf("Expected to find revision_idx 100000 for policy %s, found %d", policy.PolicyID, policy.RevisionIdx)
		}
	}
}

// TesyQueryLatestPolices11kUnique tests behaviour when 11k unique policies are used, there is a 10k size specification in the aggregation.
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
		policies, err := QueryLatestPolicies(ctx, bulker, WithIndexName(index))
		if err != nil {
			t.Fatal(err)
		}
		return len(policies) != 11000
	}, time.Second*2, time.Millisecond*100, "Expected to eventually have 11000 policies found: %d", len(policies))

	for _, policy := range policies {
		if policy.RevisionIdx != 2 {
			t.Errorf("Expected to find revision_idx 1 for policy %s, found %d", policy.PolicyID, policy.RevisionIdx)
		}
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
