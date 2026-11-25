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
	items, err := bulker.MIndex(ctx, ops, bulk.WithRefresh())
	if err != nil {
		return nil, err
	}
	for i, item := range items {
		if err := es.TranslateError(item.Status, item.Error); err != nil {
			writeErr := fmt.Errorf("write policy fixture %d: %w", i, err)
			return nil, writeErr
		}
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
	require.Equal(t, map[string]any{FiledType: testRemoteES}, policy.Data.Outputs["remote"])
}
