// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
)

var (
	tmplQueryLatestPolicies = prepareQueryLatestPolicies()
	ErrMissingAggregations  = errors.New("missing expected aggregation result")
	tmplQueryPolicies       = prepareQueryPolicies()
)

func prepareQueryLatestPolicies() []byte {
	root := dsl.NewRoot()
	root.Size(0)
	policyID := root.Aggs().Agg(FieldPolicyID)
	policyID.Terms("field", FieldPolicyID, nil).Size(10000)
	revisionIdx := policyID.Aggs().Agg(FieldRevisionIdx).TopHits()
	revisionIdx.Size(1)
	rSort := revisionIdx.Sort()
	rSort.SortOrder(FieldRevisionIdx, dsl.SortDescend)
	rSort.SortOrder(FieldCoordinatorIdx, dsl.SortDescend)
	return root.MustMarshalJSON()
}

// QueryLatestPolicies gets the latest revision for a policy
func QueryLatestPolicies(ctx context.Context, bulker bulk.Bulk, opt ...Option) ([]model.Policy, error) {
	o := newOption(FleetPolicies, opt...)
	res, err := bulker.Search(ctx, o.indexName, tmplQueryLatestPolicies, bulk.WithIgnoreUnavailble())
	if err != nil {
		return nil, err
	}

	policyID, ok := res.Aggregations[FieldPolicyID]
	if !ok {
		// Aggregation will not be here if there index is not available
		return []model.Policy{}, nil
	}
	if len(policyID.Buckets) == 0 {
		return []model.Policy{}, nil
	}
	policies := make([]model.Policy, len(policyID.Buckets))
	for i, bucket := range policyID.Buckets {
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

func prepareQueryPolicies() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Size(100)
	root.Sort().SortOrder("@timestamp", "desc")
	root.Source().Includes("data.outputs")
	tmpl.MustResolve(root)
	return tmpl
}

// query policies last updated, find the one with matching output
// can't filter on output in ES as the field is not mapped
func QueryOutputFromPolicy(ctx context.Context, bulker bulk.Bulk, outputName string, opt ...Option) (*model.Policy, error) {
	o := newOption(FleetPolicies, opt...)
	params := map[string]interface{}{}
	res, err := Search(ctx, bulker, tmplQueryPolicies, o.indexName, params)
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			zerolog.Ctx(ctx).Debug().Str("index", o.indexName).Msg(es.ErrIndexNotFound.Error())
			err = nil
		}
		return nil, err
	}
	var policy model.Policy
	for _, hit := range res.Hits {
		err = hit.Unmarshal(&policy)
		if err != nil {
			return nil, err
		}
		if policy.Data.Outputs[outputName] != nil {
			return &policy, nil
		}
	}
	zerolog.Ctx(ctx).Debug().Str(logger.PolicyOutputName, outputName).Msg("policy with output not found")
	return nil, nil
}
