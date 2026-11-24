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
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
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
<<<<<<< HEAD
	return rec, nil
=======
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
>>>>>>> e1e4620 (Fix ignored options on Fleet Server bulk writes (#8297))
}

func TestQueryLatestPolicies(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

<<<<<<< HEAD
=======
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
>>>>>>> e1e4620 (Fix ignored options on Fleet Server bulk writes (#8297))
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
