// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// policyOutputsOnly is a minimal struct for scanning policy hits in
// QueryOutputFromPolicy. Unmarshaling into this avoids deserializing the full
// model.Policy (which includes large inputs/agent config) for non-matching hits.
type policyOutputsOnly struct {
	Data *struct {
		Outputs map[string]json.RawMessage `json:"outputs"`
	} `json:"data"`
}

var (
	tmplQueryLatestPolicies = prepareQueryLatestPolicies()
	ErrMissingAggregations  = errors.New("missing expected aggregation result")
	queryPolicies           = prepareQueryPolicies()
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

func prepareQueryPolicies() []byte {
	root := dsl.NewRoot()
	root.Size(100)
	root.Sort().SortOrder("@timestamp", "desc")
	root.Source().Includes("data.outputs")
	return root.MustMarshalJSON()
}

// query policies last updated, find the one with matching output
// can't filter on output in ES as the field is not mapped
func QueryOutputFromPolicy(ctx context.Context, bulker bulk.Bulk, outputName string, opt ...Option) (*model.Policy, error) {
	o := newOption(FleetPolicies, opt...)
	res, err := bulker.Search(ctx, o.indexName, queryPolicies)
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			zerolog.Ctx(ctx).Debug().Str("index", o.indexName).Msg(es.ErrIndexNotFound.Error())
			err = nil
		}
		return nil, err
	}
	for _, hit := range res.Hits {
		var probe policyOutputsOnly
		if err = hit.Unmarshal(&probe); err != nil {
			return nil, err
		}
		if probe.Data == nil || probe.Data.Outputs[outputName] == nil {
			continue
		}
		var policy model.Policy
		if err = hit.Unmarshal(&policy); err != nil {
			return nil, err
		}
		return &policy, nil
	}
	zerolog.Ctx(ctx).Debug().Str(ecs.PolicyOutputName, outputName).Msg("policy with output not found")
	return nil, nil
}
