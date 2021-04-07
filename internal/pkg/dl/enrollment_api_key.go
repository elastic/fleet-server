// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"fmt"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

const (
	FieldApiKeyID = "api_key_id"
)

var (
	QueryEnrollmentAPIKeyByID       = prepareFindEnrollmentAPIKeyByID()
	QueryEnrollmentAPIKeyByPolicyID = prepareFindEnrollmentAPIKeyByPolicyID()
)

func prepareFindEnrollmentAPIKeyByID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	root.Query().Bool().Filter().Term(FieldApiKeyID, tmpl.Bind(FieldApiKeyID), nil)

	tmpl.MustResolve(root)
	return tmpl
}

func prepareFindEnrollmentAPIKeyByPolicyID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	root.Query().Bool().Filter().Term(FieldPolicyId, tmpl.Bind(FieldPolicyId), nil)

	tmpl.MustResolve(root)
	return tmpl
}

func FindEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, field string, id string) (rec model.EnrollmentApiKey, err error) {
	return findEnrollmentAPIKey(ctx, bulker, FleetEnrollmentAPIKeys, tmpl, field, id)
}

func findEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, index string, tmpl *dsl.Tmpl, field string, id string) (rec model.EnrollmentApiKey, err error) {
	res, err := SearchWithOneParam(ctx, bulker, tmpl, index, field, id)
	if err != nil {
		return
	}

	sz := len(res.Hits)
	if sz != 1 {
		return rec, fmt.Errorf("hit count mismatch %v", sz)
	}

	err = res.Hits[0].Unmarshal(&rec)
	return rec, err
}

func FindEnrollmentAPIKeys(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, field string, id string) ([]model.EnrollmentApiKey, error) {
	return findEnrollmentAPIKeys(ctx, bulker, FleetEnrollmentAPIKeys, tmpl, field, id)
}

func findEnrollmentAPIKeys(ctx context.Context, bulker bulk.Bulk, index string, tmpl *dsl.Tmpl, field string, id string) ([]model.EnrollmentApiKey, error) {
	res, err := SearchWithOneParam(ctx, bulker, tmpl, index, field, id)
	if err != nil {
		return nil, err
	}

	recs := make([]model.EnrollmentApiKey, len(res.Hits))
	for i := 0; i < len(res.Hits); i++ {
		if err := res.Hits[i].Unmarshal(&recs[i]); err != nil {
			return nil, err
		}
	}
	return recs, nil
}
