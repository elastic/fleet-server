// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"

	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
)

var (
	tmplQueryLatestPolicies = prepareQueryLatestPolicies()
	ErrMissingAggregations  = errors.New("missing expected aggregation result")
)

func prepareQueryLatestPolicies() []byte {
	root := dsl.NewRoot()
	root.Size(0)
	policyId := root.Aggs().Agg(FieldPolicyId)
	policyId.Terms("field", FieldPolicyId, nil).Size(10000)
	revisionIdx := policyId.Aggs().Agg(FieldRevisionIdx).TopHits()
	revisionIdx.Size(1)
	rSort := revisionIdx.Sort()
	rSort.SortOrder(FieldRevisionIdx, dsl.SortDescend)
	rSort.SortOrder(FieldCoordinatorIdx, dsl.SortDescend)
	return root.MustMarshalJSON()
}

// QueryLatestPolices gets the latest revision for a policy
func QueryLatestPolicies(ctx context.Context, bulker bulk.Bulk, opt ...Option) ([]model.Policy, error) {
	o := newOption(FleetPolicies, opt...)
	res, err := bulker.Search(ctx, o.indexName, tmplQueryLatestPolicies)
	if err != nil {
		return nil, err
	}

	policyId, ok := res.Aggregations[FieldPolicyId]
	if !ok {
		return nil, ErrMissingAggregations
	}
	if len(policyId.Buckets) == 0 {
		return []model.Policy{}, nil
	}
	policies := make([]model.Policy, len(policyId.Buckets))
	for i, bucket := range policyId.Buckets {
		revisionIdx, ok := bucket.Aggregations[FieldRevisionIdx]
		if !ok || len(revisionIdx.Hits) != 1 {
			return nil, ErrMissingAggregations
		}
		hit := revisionIdx.Hits[0]
		err = hit.Unmarshal(&policies[i])
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
	return bulker.Create(ctx, o.indexName, "", data, bulk.WithRefresh())
}
