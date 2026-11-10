// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

var (
	tmplQueryLatestPolicyByID            = prepareQueryLatestPolicyByID()
	tmplQueryDefaultFleetServerPolicyIDs = prepareQueryDefaultFleetServerPolicyIDs()
	tmplQueryLatestDefaultFlags          = prepareQueryLatestDefaultFlags()
	tmplQueryLatestPolicy                = prepareQueryLatestPolicy()
	tmplQueryPolicies                    = prepareQueryPolicies()
	tmplQueryPoliciesIndexAccess         = prepareQueryPoliciesIndexAccess()
)

var (
	ErrMissingAggregations = errors.New("missing expected aggregation result")
	ErrInvalidPolicy       = errors.New("invalid policy")
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
	o := newOption(FleetPolicies, opt...)
	// TODO: The searches are not atomic because each one can read a different state of the index.
	// A single search needs Kibana to mark only the latest revision of the default policy.
	query, err := tmplQueryDefaultFleetServerPolicyIDs.Render(nil)
	if err != nil {
		return model.Policy{}, err
	}
	res, err := bulker.Search(ctx, o.indexName, query, bulk.WithIgnoreUnavailble())
	if err != nil {
		return model.Policy{}, err
	}
	buckets := res.Aggregations[FieldPolicyID].Buckets
	if len(buckets) == 0 {
		return model.Policy{}, ErrNotFound
	}
	policyIDs := make([]string, len(buckets))
	for i, bucket := range buckets {
		policyIDs[i] = bucket.Key
	}

	// Many policies can have been the default, so only the default policy is loaded in full.
	query, err = tmplQueryLatestDefaultFlags.RenderOne(FieldPolicyID, policyIDs)
	if err != nil {
		return model.Policy{}, err
	}
	res, err = bulker.Search(ctx, o.indexName, query, bulk.WithIgnoreUnavailble())
	if err != nil {
		return model.Policy{}, err
	}
	policies, err := appendLatestPolicies(nil, res.Aggregations, NewStringSharer())
	if err != nil {
		return model.Policy{}, err
	}
	for _, policy := range policies {
		// Policies that are not the default anymore are also returned at their latest revision.
		if policy.DefaultFleetServer {
			return QueryLatestPolicyByID(ctx, bulker, policy.PolicyID, opt...)
		}
	}
	return model.Policy{}, ErrNotFound
}

func prepareQueryDefaultFleetServerPolicyIDs() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Size(0)
	root.Query().Bool().Filter().Term(FieldDefaultFleetServer, true, nil)
	root.Aggs().Agg(FieldPolicyID).Terms("field", FieldPolicyID, nil).Size(10000)
	tmpl.MustResolve(root)
	return tmpl
}

func prepareQueryLatestDefaultFlags() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Size(0)
	root.Query().Bool().Filter().Terms(FieldPolicyID, tmpl.Bind(FieldPolicyID), nil)
	addLatestRevisionAggs(root, FieldPolicyID, FieldRevisionIdx, FieldDefaultFleetServer)
	tmpl.MustResolve(root)
	return tmpl
}

// QueryLatestPoliciesByID gets the latest revision of each of the given policies.
func QueryLatestPoliciesByID(ctx context.Context, bulker bulk.Bulk, policyIDs []string, opt ...Option) ([]model.Policy, error) {
	if len(policyIDs) == 0 {
		return nil, nil
	}
	o := newOption(FleetPolicies, opt...)
	ops := make([]bulk.MultiOp, len(policyIDs))
	for i, policyID := range policyIDs {
		query, err := tmplQueryLatestPolicy.RenderOne(FieldPolicyID, policyID)
		if err != nil {
			return nil, err
		}
		ops[i] = bulk.MultiOp{
			Index: o.indexName,
			Body:  query,
		}
	}
	items, searchErr := bulker.MSearch(ctx, ops, append(o.bulkOpts, bulk.WithIgnoreUnavailble())...)
	if len(items) == 0 {
		return nil, searchErr
	}
	policies := make([]model.Policy, 0, len(items))
	sharer := NewStringSharer()
	var errs []error
	for i, policyID := range policyIDs {
		item := items[i]
		var err error
		switch item.Status {
		case http.StatusOK:
			var found []model.Policy
			if found, err = appendLatestPolicies(policies, item.Aggregations, sharer); err != nil {
				err = fmt.Errorf("policy %s: %w: %w", policyID, ErrInvalidPolicy, err)
			} else {
				policies = found
			}
		case 0:
			// The request of this search failed and searchErr holds its error.
			err = searchErr
		default:
			err = es.TranslateError(item.Status, item.Error)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		// Remove the consecutive copies of a request error because a failed request gives the same
		// error to each of its searches.
		uniqueErrs := errors.Join(slices.Compact(errs)...)
		return policies, fmt.Errorf("search failed for %d of %d policies: %w", len(errs), len(policyIDs), uniqueErrs)
	}
	return policies, nil
}

func prepareQueryLatestPolicy() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Size(0)
	root.Query().Bool().Filter().Term(FieldPolicyID, tmpl.Bind(FieldPolicyID), nil)
	addLatestRevisionAggs(root)
	tmpl.MustResolve(root)
	return tmpl
}

func addLatestRevisionAggs(root *dsl.Node, fields ...string) {
	policyID := root.Aggs().Agg(FieldPolicyID)
	policyID.Terms("field", FieldPolicyID, nil).Size(10000)
	revisionIdx := policyID.Aggs().Agg(FieldRevisionIdx).TopHits()
	revisionIdx.Size(1)
	rSort := revisionIdx.Sort()
	rSort.SortOrder(FieldRevisionIdx, dsl.SortDescend)
	if len(fields) > 0 {
		revisionIdx.Source().Includes(fields...)
	}
}

func appendLatestPolicies(policies []model.Policy, aggregations map[string]es.Aggregation, sharer *StringSharer) ([]model.Policy, error) {
	policyID, ok := aggregations[FieldPolicyID]
	if !ok {
		// Aggregation will not be here if there index is not available
		return policies, nil
	}
	for _, bucket := range policyID.Buckets {
		revisionIdx, ok := bucket.Aggregations[FieldRevisionIdx]
		if !ok || len(revisionIdx.Hits) != 1 {
			return nil, ErrMissingAggregations
		}
		var policy model.Policy
		if err := revisionIdx.Hits[0].Unmarshal(&policy); err != nil {
			return nil, err
		}
		sharer.Share(&policy)
		policies = append(policies, policy)
	}
	return policies, nil
}

// QueryOutputFromPolicy gets the most recently updated policy that has the given output, or nil if
// none has it. It searches the 100 latest policies because the outputs field is not mapped.
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
	query, err := tmplQueryPoliciesIndexAccess.Render(nil)
	if err != nil {
		return err
	}
	_, err = bulker.Search(ctx, o.indexName, query, bulk.WithIgnoreUnavailble())
	return err
}

func prepareQueryPoliciesIndexAccess() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Size(0)
	tmpl.MustResolve(root)
	return tmpl
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
