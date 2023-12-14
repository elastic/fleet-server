// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

const (
	FieldAPIKeyID = "api_key_id"
)

var (
	QueryEnrollmentAPIKeyByID       = prepareFindActiveEnrollmentAPIKeyByID()
	QueryEnrollmentAPIKeyByPolicyID = prepareFindActiveEnrollmentAPIKeyByPolicyID()
)

func prepareFindActiveEnrollmentAPIKeyByID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	filter := root.Query().Bool().Filter()
	filter.Term(FieldAPIKeyID, tmpl.Bind(FieldAPIKeyID), nil)
	filter.Term(FieldActive, true, nil)

	tmpl.MustResolve(root)
	return tmpl
}

func prepareFindActiveEnrollmentAPIKeyByPolicyID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	filter := root.Query().Bool().Filter()
	filter.Term(FieldPolicyID, tmpl.Bind(FieldPolicyID), nil)
	filter.Term(FieldActive, true, nil)

	tmpl.MustResolve(root)
	return tmpl
}

func FindEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, field string, id string) (rec model.EnrollmentAPIKey, err error) {
	return findEnrollmentAPIKey(ctx, bulker, FleetEnrollmentAPIKeys, tmpl, field, id)
}

func findEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, index string, tmpl *dsl.Tmpl, field string, id string) (model.EnrollmentAPIKey, error) {
	var rec model.EnrollmentAPIKey
	res, err := SearchWithOneParam(ctx, bulker, tmpl, index, field, id)
	if err != nil {
		return rec, err
	}

	sz := len(res.Hits)
	if sz != 1 {
		return rec, fmt.Errorf("hit count mismatch %v", sz)
	}

	err = res.Hits[0].Unmarshal(&rec)
	return rec, err
}

func FindEnrollmentAPIKeys(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, field string, id string) ([]model.EnrollmentAPIKey, error) {
	return findEnrollmentAPIKeys(ctx, bulker, FleetEnrollmentAPIKeys, tmpl, field, id)
}

func findEnrollmentAPIKeys(ctx context.Context, bulker bulk.Bulk, index string, tmpl *dsl.Tmpl, field string, id string) ([]model.EnrollmentAPIKey, error) {
	res, err := SearchWithOneParam(ctx, bulker, tmpl, index, field, id)
	if err != nil {
		return nil, err
	}

	recs := make([]model.EnrollmentAPIKey, len(res.Hits))
	for i := 0; i < len(res.Hits); i++ {
		if err := res.Hits[i].Unmarshal(&recs[i]); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

// CreateEnrollmentAPIKey creates a new enrollment API key
func CreateEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, key model.EnrollmentAPIKey, opt ...Option) (string, error) {
	o := newOption(FleetEnrollmentAPIKeys, opt...)
	data, err := json.Marshal(&key)
	if err != nil {
		return "", err
	}
	return bulker.Create(ctx, o.indexName, "", data, bulk.WithRefresh())
}
