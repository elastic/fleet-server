// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package dl

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
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

func createRandomPolicyFromRevision(id string, revision model.Policy) model.Policy {
	policy := createRandomPolicy(id, int(revision.RevisionIdx))
	policy.DefaultFleetServer = revision.DefaultFleetServer
	return policy
}

func storeRandomPolicies(ctx context.Context, bulker bulk.Bulk, index string, policies [][]model.Policy) ([]string, error) {
	ids := make([]string, len(policies))
	var ops []bulk.MultiOp
	for i, revisions := range policies {
		ids[i] = uuid.Must(uuid.NewV4()).String()
		for _, revision := range revisions {
			rec := createRandomPolicyFromRevision(ids[i], revision)
			p, err := json.Marshal(&rec)
			if err != nil {
				return nil, err
			}
			ops = append(ops, bulk.MultiOp{
				Index: index,
				Body:  p,
			})
		}
	}
	_, err := bulker.MIndex(ctx, ops)
	if err != nil {
		return nil, err
	}
	// TODO: Use bulk.WithRefresh in MIndex when it applies the option, see
	// https://github.com/elastic/fleet-server/issues/8222.
	cli := bulker.Client()
	res, err := cli.Indices.Refresh(
		cli.Indices.Refresh.WithContext(ctx),
		cli.Indices.Refresh.WithIndex(index),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.IsError() {
		return nil, fmt.Errorf("refresh %s: %s", index, res.Status())
	}
	return ids, nil
}

func TestQueryDefaultFleetServerPolicyIntegration(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies, bulk.WithFlushThresholdCount(1))

	// Create 2 default policies. Policy 0 is the default because it is the policy whose latest
	// revision sets default_fleet_server.
	defaultPolicies := [][]model.Policy{
		// Policy 0
		{
			{RevisionIdx: 1, DefaultFleetServer: true},
			{RevisionIdx: 2, DefaultFleetServer: true},
		},
		// Policy 1
		{
			{RevisionIdx: 1, DefaultFleetServer: true},
			{RevisionIdx: 2, DefaultFleetServer: true},
			{RevisionIdx: 3, DefaultFleetServer: true},
			{RevisionIdx: 4, DefaultFleetServer: false},
		},
	}
	defaultIDs, err := storeRandomPolicies(ctx, bulker, index, defaultPolicies)
	require.NoError(t, err)

	policy, err := QueryLatestPolicy(ctx, bulker, "", WithIndexName(index), WithDefaultFleetServerFallback())
	require.NoError(t, err)
	require.Equal(t, defaultIDs[0], policy.PolicyID)
	require.Equal(t, int64(2), policy.RevisionIdx)
	require.NotNil(t, policy.Data, "the default policy is loaded with its content")
	assert.Contains(t, policy.Data.Outputs, testDefaultOutput)
}

// TestQueryLatestPolicy400k tests to see if  to see if the latest revision is correctly selected when a lot the revision count is very large
func TestQueryLatestPolicy400k(t *testing.T) {
	t.Skip("Test flaky, see: https://github.com/elastic/fleet-server/issues/5181")
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies, bulk.WithFlushThresholdCount(1))

<<<<<<< HEAD
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
	}, time.Second*2, time.Millisecond*100, "Expected to eventually have 4 policies found: %d", len(policies))

	for _, policy := range policies {
		if policy.RevisionIdx != 100000 {
			t.Errorf("Expected to find revision_idx 100000 for policy %s, found %d", policy.PolicyID, policy.RevisionIdx)
=======
	policies := make([][]model.Policy, 4)
	for i := range policies {
		policies[i] = make([]model.Policy, 100000)
		for j := range policies[i] {
			policies[i][j].RevisionIdx = int64(j + 1)
>>>>>>> 39eeea5 (Load only the needed policies in Fleet Server health checks and enrollments (#8224))
		}
	}
	ids, err := storeRandomPolicies(ctx, bulker, index, policies)
	require.NoError(t, err)

<<<<<<< HEAD
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
=======
	for _, id := range ids {
		var policy model.Policy
		require.Eventually(t, func() bool {
			policy, err = QueryLatestPolicy(ctx, bulker, id, WithIndexName(index))
			return err == nil && policy.RevisionIdx == 100000
		}, time.Second*2, time.Millisecond*100, "Expected revision_idx 100000 for policy %s, found %d, error: %v", id, policy.RevisionIdx, err)
>>>>>>> 39eeea5 (Load only the needed policies in Fleet Server health checks and enrollments (#8224))
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
