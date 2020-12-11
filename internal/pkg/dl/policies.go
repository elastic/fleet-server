// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"errors"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/model"
	"fmt"
	"sync"

	"fleet/internal/pkg/dsl"
)

var (
	tmplQueryLatestPolicies     []byte
	initQueryLatestPoliciesOnce sync.Once
)

var ErrPolicyLeaderNotFound = errors.New("policy has no leader")

func prepareQueryLatestPolicies() []byte {
	root := dsl.NewRoot()
	root.Size(0)
	policyId := root.Aggs().Agg(FieldPolicyId)
	policyId.Terms("field", FieldPolicyId, nil)
	revisionIdx := policyId.Aggs().Agg(FieldRevisionIdx).TopHits()
	revisionIdx.Size(1)
	rSort := revisionIdx.Sort()
	rSort.SortOrder(FieldRevisionIdx, dsl.SortDescend)
	rSort.SortOrder(FieldCoordinatorIdx, dsl.SortDescend)
	return root.MustMarshalJSON()
}

// QueryLatestPolices gets the latest revision for a policy
func QueryLatestPolicies(ctx context.Context, bulker bulk.Bulk, opt ...Option) ([]model.Policy, error) {
	initQueryLatestPoliciesOnce.Do(func() {
		tmplQueryLatestPolicies = prepareQueryLatestPolicies()
	})

	o := newOption(FleetPolicies, opt...)
	aggErr := fmt.Errorf("missing expected aggregation result")
	res, err := bulker.Search(ctx, []string{o.indexName}, tmplQueryLatestPolicies)
	if err != nil {
		return nil, err
	}

	policyId, ok := res.Aggregations[FieldPolicyId]
	if !ok {
		return nil, aggErr
	}
	if len(policyId.Buckets) == 0 {
		return []model.Policy{}, nil
	}
	policies := make([]model.Policy, len(policyId.Buckets))
	for i, bucket := range policyId.Buckets {
		revisionIdx, ok := bucket.Aggregations[FieldRevisionIdx]
		if !ok || len(revisionIdx.Hits) != 1 {
			return nil, aggErr
		}
		hit := revisionIdx.Hits[0]
		err = json.Unmarshal(hit.Source, &policies[i])
		if err != nil {
			return nil, err
		}
	}
	return policies, nil
}

// CreatePolicy creates a new policy in the index
func CreatePolicy(ctx context.Context, bulker bulk.Bulk, policy model.Policy, opt ...Option) (string, error) {
	o := newOption(FleetPolicies, opt...)
	data, err := json.Marshal(&policy)
	if err != nil {
		return "", err
	}
	return bulker.Create(ctx, o.indexName, "", data)
}
