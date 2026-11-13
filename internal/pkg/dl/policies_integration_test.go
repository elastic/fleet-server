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
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func createRandomPolicyFromRevision(id string, revision model.Policy) model.Policy {
	now := time.Now().UTC()
	var policyData = model.PolicyData{
		Outputs: map[string]map[string]any{
			"default": {
				"type": "elasticsearch",
			},
		},
		OutputPermissions: json.RawMessage(`{"default": {}}`),
		Inputs:            []map[string]any{},
	}
	return model.Policy{
		PolicyID:           id,
		RevisionIdx:        revision.RevisionIdx,
		Data:               &policyData,
		DefaultFleetServer: revision.DefaultFleetServer,
		Timestamp:          now.Format(time.RFC3339),
	}
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

func TestQueryLatestPolicy(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())
	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies, bulk.WithFlushThresholdCount(1))

	// Create 2 policies with 2 revisions each.
	policies := [][]model.Policy{
		// Policy 0
		{
			{RevisionIdx: 1},
			{RevisionIdx: 2},
		},
		// Policy 1
		{
			{RevisionIdx: 1},
			{RevisionIdx: 2},
		},
	}
	ids, err := storeRandomPolicies(ctx, bulker, index, policies)
	require.NoError(t, err)

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

	tests := []struct {
		name            string
		policyID        string
		opts            []Option
		wantPolicyID    string
		wantRevisionIdx int64
	}{
		{
			name:            "returns the latest revision of the policy",
			policyID:        ids[0],
			wantPolicyID:    ids[0],
			wantRevisionIdx: 2,
		},
		{
			name:            "returns the default policy when no policy ID is set",
			policyID:        "",
			opts:            []Option{WithDefaultFleetServerFallback()},
			wantPolicyID:    defaultIDs[0],
			wantRevisionIdx: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]Option{WithIndexName(index)}, tc.opts...)
			policy, err := QueryLatestPolicy(ctx, bulker, tc.policyID, opts...)
			require.NoError(t, err)
			require.Equal(t, tc.wantPolicyID, policy.PolicyID)
			require.Equal(t, tc.wantRevisionIdx, policy.RevisionIdx)
		})
	}
}

// TestQueryLatestPolicy400k tests to see if  to see if the latest revision is correctly selected when a lot the revision count is very large
//
//nolint:dupl // test duplication
func TestQueryLatestPolicy400k(t *testing.T) {
	t.Skip("Test flaky, see: https://github.com/elastic/fleet-server/issues/5181")
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies, bulk.WithFlushThresholdCount(1))

	policies := make([][]model.Policy, 4)
	for i := range policies {
		policies[i] = make([]model.Policy, 100000)
		for j := range policies[i] {
			policies[i][j].RevisionIdx = int64(j + 1)
		}
	}
	ids, err := storeRandomPolicies(ctx, bulker, index, policies)
	require.NoError(t, err)

	for _, id := range ids {
		var policy model.Policy
		require.Eventually(t, func() bool {
			policy, err = QueryLatestPolicy(ctx, bulker, id, WithIndexName(index))
			return err == nil && policy.RevisionIdx == 100000
		}, time.Second*2, time.Millisecond*100, "Expected revision_idx 100000 for policy %s, found %d, error: %v", id, policy.RevisionIdx, err)
	}
}

func TestCreatePolicy(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetPolicies)

	policyID := uuid.Must(uuid.NewV4()).String()
	p := createRandomPolicyFromRevision(policyID, model.Policy{RevisionIdx: 1})
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
				"type": "remote_elasticsearch",
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
	require.Equal(t, map[string]any{"type": "remote_elasticsearch"}, policy.Data.Outputs["remote"])
}
