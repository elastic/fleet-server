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

// QueryLatestPolicy gets the latest revision of the policy. With WithDefaultFleetServerFallback it
// gets the default Fleet Server policy when the policy ID is empty.
func QueryLatestPolicy(ctx context.Context, bulker bulk.Bulk, policyID string, opt ...Option) (model.Policy, error) {
	o := newOption(FleetPolicies, opt...)
	if policyID != "" {
		return QueryLatestPolicyByID(ctx, bulker, policyID, opt...)
	}
	if o.defaultFleetServerFallback {
		return QueryDefaultFleetServerPolicy(ctx, bulker, opt...)
	}
	return model.Policy{}, ErrNotFound
}

// QueryLatestPolicyByID gets the latest revision of the policy with the given ID.
func QueryLatestPolicyByID(ctx context.Context, bulker bulk.Bulk, policyID string, opt ...Option) (model.Policy, error) {
	o := newOption(FleetPolicies, opt...)
	query, err := tmplQueryLatestPolicyByID.RenderOne(FieldPolicyID, policyID)
	if err != nil {
		return model.Policy{}, err
	}
	res, err := bulker.Search(ctx, o.indexName, query, bulk.WithIgnoreUnavailble())
	if err != nil {
		return model.Policy{}, err
	}
	if len(res.Hits) == 0 {
		return model.Policy{}, ErrNotFound
	}
	var policy model.Policy
	if err := res.Hits[0].Unmarshal(&policy); err != nil {
		return model.Policy{}, err
	}
	NewStringSharer().Share(&policy)
	return policy, nil
}

var tmplQueryLatestPolicyByID = prepareQueryLatestPolicyByID()

func prepareQueryLatestPolicyByID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Size(1)
	root.Query().Bool().Filter().Term(FieldPolicyID, tmpl.Bind(FieldPolicyID), nil)
	root.Sort().SortOrder(FieldRevisionIdx, dsl.SortDescend)
	tmpl.MustResolve(root)
	return tmpl
}

// QueryDefaultFleetServerPolicy gets the latest revision of the default Fleet Server policy.
func QueryDefaultFleetServerPolicy(ctx context.Context, bulker bulk.Bulk, opt ...Option) (model.Policy, error) {
	// TODO: This is not atomic, the two queries can read different states of the index. Kibana
	// must make the latest default policy unique to allow a single search (e.g. dedicated ts).
	policyIDs, err := QueryDefaultFleetServerPolicyIDs(ctx, bulker, opt...)
	if err != nil {
		return model.Policy{}, err
	}
	policies, err := QueryLatestPoliciesByID(ctx, bulker, policyIDs, opt...)
	if err != nil {
		return model.Policy{}, err
	}
	for _, policy := range policies {
		// Policies that are not the default anymore are also returned at their latest revision.
		if policy.DefaultFleetServer {
			return policy, nil
		}
	}
	return model.Policy{}, ErrNotFound
}

// QueryDefaultFleetServerPolicyIDs gets the IDs of the policies that have a revision marked as
// default_fleet_server.
func QueryDefaultFleetServerPolicyIDs(ctx context.Context, bulker bulk.Bulk, opt ...Option) ([]string, error) {
	o := newOption(FleetPolicies, opt...)
	query := queryDefaultFleetServerPolicyIDs
	res, err := bulker.Search(ctx, o.indexName, query, bulk.WithIgnoreUnavailble())
	if err != nil {
		return nil, err
	}

	buckets := res.Aggregations[FieldPolicyID].Buckets
	policyIDs := make([]string, len(buckets))
	for i, bucket := range buckets {
		policyIDs[i] = bucket.Key
	}
	return policyIDs, nil
}

var queryDefaultFleetServerPolicyIDs = prepareQueryDefaultFleetServerPolicyIDs()

func prepareQueryDefaultFleetServerPolicyIDs() []byte {
	root := dsl.NewRoot()
	root.Size(0)
	root.Query().Bool().Filter().Term(FieldDefaultFleetServer, true, nil)
	root.Aggs().Agg(FieldPolicyID).Terms("field", FieldPolicyID, nil).Size(10000)
	return root.MustMarshalJSON()
}

// QueryLatestPoliciesByID gets the latest revision of each of the policies.
func QueryLatestPoliciesByID(ctx context.Context, bulker bulk.Bulk, policyIDs []string, opt ...Option) ([]model.Policy, error) {
	if len(policyIDs) == 0 {
		return nil, nil
	}
	o := newOption(FleetPolicies, opt...)
	query, err := tmplQueryLatestPoliciesByID.Render(map[string]any{
		FieldPolicyID: policyIDs,
		FieldSize:     len(policyIDs),
	})
	if err != nil {
		return nil, err
	}
	res, err := bulker.Search(ctx, o.indexName, query, bulk.WithIgnoreUnavailble())
	if err != nil {
		return nil, err
	}

	policies := make([]model.Policy, len(res.Hits))
	sharer := NewStringSharer()
	for i, hit := range res.Hits {
		if err := hit.Unmarshal(&policies[i]); err != nil {
			return nil, err
		}
		sharer.Share(&policies[i])
	}
	return policies, nil
}

var tmplQueryLatestPoliciesByID = prepareQueryLatestPoliciesByID()

func prepareQueryLatestPoliciesByID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Bool().Filter().Terms(FieldPolicyID, tmpl.Bind(FieldPolicyID), nil)
	root.WithSize(tmpl.Bind(FieldSize))
	root.Param("collapse", map[string]string{"field": FieldPolicyID})
	root.Sort().SortOrder(FieldRevisionIdx, dsl.SortDescend)
	tmpl.MustResolve(root)
	return tmpl
}

// query policies last updated, find the one with matching output
// can't filter on output in ES as the field is not mapped
func QueryOutputFromPolicy(ctx context.Context, bulker bulk.Bulk, outputName string, opt ...Option) (*model.Policy, error) {
	o := newOption(FleetPolicies, opt...)
	params := map[string]any{}
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
	zerolog.Ctx(ctx).Debug().Str(ecs.PolicyOutputName, outputName).Msg("policy with output not found")
	return nil, nil
}

var tmplQueryPolicies = prepareQueryPolicies()

func prepareQueryPolicies() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Size(100)
	root.Sort().SortOrder("@timestamp", "desc")
	root.Source().Includes("data.outputs")
	tmpl.MustResolve(root)
	return tmpl
}

// CheckPoliciesIndexAccess checks that the policies index can be searched. A missing index is not an error.
func CheckPoliciesIndexAccess(ctx context.Context, bulker bulk.Bulk, opt ...Option) error {
	o := newOption(FleetPolicies, opt...)
	query := queryPoliciesIndexAccess
	_, err := bulker.Search(ctx, o.indexName, query, bulk.WithIgnoreUnavailble())
	return err
}

var queryPoliciesIndexAccess = prepareQueryPoliciesIndexAccess()

func prepareQueryPoliciesIndexAccess() []byte {
	root := dsl.NewRoot()
	root.Size(0)
	return root.MustMarshalJSON()
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
